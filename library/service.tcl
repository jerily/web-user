#
# Copyright Jerily LTD. All Rights Reserved.
# SPDX-FileCopyrightText: 2026 Neofytos Dimitriou (neo@jerily.cy)
# SPDX-License-Identifier: MIT.
#

# Each action runs inside the shared request transaction. Delivery follows commit.
proc ::web::user::action_login {config row fields} {
    set store [dict get $config -store]
    set result [dict create message {} debug_code {} delivery {}]
    set address [email [dict get $fields email]]
    set user [user_by_email $store $address]
    if {$user eq {}} {
        # Match a normal password verification's work for an unknown address.
        ::bcrypt::hashpw [random_token] [::bcrypt::gensalt [property $store bcrypt_cost]]
        fail 401 "Invalid email or password."
    }
    if {![password_ok $store $user [dict get $fields password]] || ![dict get $user active]} {fail 401 "Invalid email or password."}
    set kind [expr {[dict get $user mfa_secret] eq {} ? "auth" : "two-factor"}]
    set changes {}
    if {$kind eq "auth"} {set changes [dict create last_login_at [clock seconds] last_seen_at [clock seconds]]}
    save_user $store $user $changes
    set staySignedIn [expr {[dict exists $fields stay_signed_in] && [dict get $fields stay_signed_in] eq "1"}]
    dict set result token [rotate $store $row $kind [dict get $user id] {} $staySignedIn]
    dict set result view [expr {$kind eq "auth" ? "account" : "two-factor"}]
    return $result
}

# Issue a session-bound reset challenge for an active account.
proc ::web::user::action_forgot {config row fields} {
    set store [dict get $config -store]
    set result [dict create message {} debug_code {} delivery {}]
    set address [email [dict get $fields email]]
    set user [user_by_email $store $address]
    set code [verification_code]
    set uid {}
    if {$user ne {} && [dict get $user active]} {
        set uid [dict get $user id]
        dict set result delivery [list reset $address $code]
        dict set result debug_code $code
    }
    dict set result token [rotate $store $row reset $uid $code]
    dict set result view reset
    dict set result message {If the account exists, use the password reset code sent to your email.}
    return $result
}

# Change the password once, verify email ownership and revoke old sessions.
proc ::web::user::action_reset {config row fields} {
    set store [dict get $config -store]
    set uid [dict get $row uid]
    set result [dict create message {} debug_code {} delivery {}]
    check_code $store $row reset [dict get $fields code]
    set user [user_by_id $store $uid]
    if {$user eq {}} {fail 400 "Invalid or expired code."}
    set hash [password_hash [dict get $fields password] [dict get $store -config]]
    save_user $store $user [dict create password [seal $store $hash [list password-hash $uid]] verified 1]
    # Reset does not remove MFA and never signs the browser in automatically.
    revoke $store $uid
    dict set result token [new_session $store]
    dict set result view login
    dict set result message {Password changed. Sign in again.}
    dict set result delivery [notification $store $user password-changed]
    return $result
}

# Verify current credentials and replace the password atomically.
proc ::web::user::action_change_password {config row fields} {
    set store [dict get $config -store]
    set user [require_user $store $row]
    if {![password_ok $store $user [dict get $fields current_password]]} {fail 401 "Invalid current password."}
    if {[dict get $fields password] ne [dict get $fields confirm_password]} {fail 400 "New passwords do not match."}
    set hash [password_hash [dict get $fields password] [dict get $store -config]]
    set uid [dict get $user id]
    save_user $store $user [dict create password [seal $store $hash [list password-hash $uid]]]
    revoke $store $uid
    # Keep this authenticated browser signed in with a fresh token. MFA settings
    # and replay state remain unchanged; all old sessions/challenges are revoked.
    return [dict create token [new_session $store auth $uid {} [session_persistent $row]] view account \
        message {Password changed. Other sessions were signed out.} debug_code {} \
        delivery [notification $store $user password-changed]]
}

# Permanently remove this account after rechecking its current password.
proc ::web::user::action_close_account {config row fields} {
    set store [dict get $config -store]
    set user [require_user $store $row]
    if {![password_ok $store $user [dict get $fields current_password]]} {fail 401 "Invalid current password."}
    # Serialize closure with password/profile/MFA changes before removing data.
    set user [save_user $store $user {}]
    set uid [dict get $user id]
    foreach pending [rows $store web_user_registrations [dict create email_key [dict get $user email_key]]] {
        set id [dict get $pending id]
        revoke $store $id
        remove $store web_user_registrations [dict create id $id]
    }
    revoke $store $uid
    remove $store web_user_profiles [dict create id $uid]
    if {[remove $store web_user_users [dict create id $uid revision [dict get $user revision]]] != 1} {
        fail 409 "Account changed; retry the request."
    }
    return [dict create token [new_session $store] view login \
        message {Your account has been closed.} debug_code {} delivery {}]
}

# Complete the pending authenticator challenge without permitting replay.
proc ::web::user::action_two_factor {config row fields} {
    set store [dict get $config -store]
    set uid [dict get $row uid]
    set result [dict create message {} debug_code {} delivery {}]
    if {[dict get $row kind] ne "two-factor"} {fail 401 "Sign in with your password first."}
    set user [user_by_id $store $uid]
    if {$user eq {} || ![dict get $user active] || [dict get $user mfa_secret] eq {}} {fail 401 "Sign in again."}
    set secret [unseal $store [dict get $user mfa_secret] [list mfa $uid]]
    set step [totp_step $store $secret [dict get $fields code] [dict get $user last_step]]
    if {$step < 0} {
        return -code error -errorcode {WEB USER 401 TOTP} \
            "That authenticator code is invalid or has already been used. Wait for the next code in your authenticator app, then try again."
    }
    save_user $store $user [dict create last_step $step last_login_at [clock seconds] last_seen_at [clock seconds]]
    dict set result token [rotate $store $row auth $uid {} [session_persistent $row]]
    dict set result view account
    return $result
}

# Enroll an authenticator only after verified email and password checks.
proc ::web::user::action_two_factor_setup {config row fields} {
    set store [dict get $config -store]
    set uid [dict get $row uid]
    set result [dict create message {} debug_code {} delivery {}]
    set user [require_user $store $row]
    if {![dict get $user verified]} {fail 403 "Verify your email before enabling an authenticator."}
    if {[dict get $user mfa_secret] ne {}} {fail 409 "Two-factor authentication is already enabled."}
    if {[dict get $fields operation] eq "begin"} {
        if {![password_ok $store $user [dict get $fields password]]} {fail 401 "Invalid password."}
        set secret [string trimright [::tmfa::base32_encode [::twebserver::random_bytes 20]] =]
        if {[::tsession::sql::update [dict get $store -sessions] [dict get $row id] \
            [dict create pending_secret [seal $store $secret [list mfa $uid]] expires [expr {[clock seconds] + [property $store challenge_ttl]}]]] != 1} {
            fail 409 "Session changed; retry the request."
        }
        dict set result token {}
        dict set result view two-factor/setup
    } elseif {[dict get $fields operation] eq "confirm"} {
        if {[dict get $row pending_secret] eq {}} {fail 400 "Start authenticator setup first."}
        set secret [unseal $store [dict get $row pending_secret] [list mfa $uid]]
        set step [totp_step $store $secret [dict get $fields code] -1]
        if {$step < 0} {fail 401 "Invalid authenticator code."}
        save_user $store $user [dict create mfa_secret [dict get $row pending_secret] last_step $step]
        revoke $store $uid
        dict set result token [new_session $store auth $uid {} [session_persistent $row]]
        dict set result view account
        dict set result message {Two-factor authentication enabled. Other sessions were signed out.}
        dict set result delivery [notification $store $user mfa-enabled]
    } else {fail 400 "Unknown setup operation."}
    return $result
}

# Remove an authenticator after checking both password and OTP.
proc ::web::user::action_two_factor_disable {config row fields} {
    set store [dict get $config -store]
    set uid [dict get $row uid]
    set result [dict create message {} debug_code {} delivery {}]
    set user [require_user $store $row]
    if {![password_ok $store $user [dict get $fields password]] || [dict get $user mfa_secret] eq {}} {fail 401 "Invalid credentials."}
    set secret [unseal $store [dict get $user mfa_secret] [list mfa $uid]]
    if {[totp_step $store $secret [dict get $fields code] [dict get $user last_step]] < 0} {fail 401 "Invalid or already used authenticator code."}
    save_user $store $user {mfa_secret {} last_step -1}
    revoke $store $uid
    dict set result token [new_session $store auth $uid {} [session_persistent $row]]
    dict set result view account
    dict set result message {Two-factor authentication disabled. Other sessions were signed out.}
    dict set result delivery [notification $store $user mfa-disabled]
    return $result
}

# Replace the authenticated session with an anonymous session.
proc ::web::user::action_logout {config row fields} {
    set store [dict get $config -store]
    set result [dict create message {} debug_code {} delivery {}]
    dict set result token [rotate $store $row anon]
    dict set result view login
    dict set result message {You have signed out.}
    return $result
}

# Require an authenticated active account.
proc ::web::user::require_user {store row} {
    set user [authenticated $store $row]
    if {$user eq {}} {fail 401 "Sign in first."}
    return $user
}
# Validate the challenge purpose and its stored code verifier.
proc ::web::user::check_code {store row kind code} {
    if {[dict get $row kind] ne $kind || [dict get $row uid] eq {} ||
        ![verify_tag $store [dict get $row code_tag] $code [list code [dict get $row id]]]} {
        fail 400 "Invalid or expired code."
    }
}

# Update configured profile fields while preserving unique public handles.
proc ::web::user::action_profile {config row fields} {
    set store [dict get $config -store]
    set user [require_user $store $row]
    set names [name_fields $store $fields]
    set changes {}
    if {[property $store collect_username]} {
        set username [username_field $store $fields]
        check_username $store $username [dict get $user id]
        dict set changes username $username
    }
    # A savepoint lets PostgreSQL inspect the winning username after a race.
    if {[catch {
        db_transaction [dict get $store -connection] {save_user $store $user $changes}
    } message opts]} {
        if {[dict exists $changes username]} {check_username $store $username [dict get $user id]}
        return -options $opts $message
    }
    save_profile $store [dict get $user id] $names
    dict create token {} view account message {Profile updated.} debug_code {} delivery {}
}
