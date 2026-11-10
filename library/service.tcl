# Each action runs inside the shared request transaction. Delivery follows commit.
proc ::web::user::action_register {config row fields} {
    set store [dict get $config -store]
    set uid [dict get $row uid]
    set result [dict create message {} debug_code {} delivery {}]
    set address [email [dict get $fields email]]
    set hash [password_hash [dict get $fields password] [dict get $store -config]]
    set emailKey [tag $store $address email]
    set user [one $store web_user_users [dict create email_key $emailKey]]
    set code [random_token]
    set uid {}
    if {$user eq {}} {
        set uid [::ksuid::generate_ksuid]
        insert $store web_user_users [dict create id $uid email_key $emailKey \
            email [seal $store $address [list email $uid]] password $hash verified 0 \
            mfa_secret {} last_step -1 revision 0 created_at [clock seconds]]
    } elseif {![dict get $user verified]} {
        # Retry expired/lost verification with a new password/code pair.
        set uid [dict get $user id]
        save_user $store $user [dict create password $hash]
        revoke $store $uid
        if {[dict get $row uid] eq $uid} {set row {}}
    }
    if {$uid ne {}} {
        dict set result delivery [list verify $address $code]
        dict set result debug_code $code
    }
    dict set result token [rotate $store $row verify $uid $code]
    dict set result view verify
    dict set result message {If registration is available, use the verification code sent to your email.}
    return $result
}

proc ::web::user::action_verify {config row fields} {
    set store [dict get $config -store]
    set uid [dict get $row uid]
    set result [dict create message {} debug_code {} delivery {}]
    check_code $store $row verify [dict get $fields code]
    set user [user_by_id $store $uid]
    if {$user eq {} || [dict get $user verified]} {fail 400 "Invalid or expired code."}
    save_user $store $user {verified 1}
    dict set result token [rotate $store $row anon]
    dict set result view login
    dict set result message {Email verified. You can now sign in.}
    return $result
}

proc ::web::user::action_login {config row fields} {
    set store [dict get $config -store]
    set uid [dict get $row uid]
    set result [dict create message {} debug_code {} delivery {}]
    set address [email [dict get $fields email]]
    set user [one $store web_user_users [dict create email_key [tag $store $address email]]]
    if {$user eq {}} {
        # Match a normal password verification's work for an unknown address.
        ::bcrypt::hashpw [random_token] [::bcrypt::gensalt [property $store bcrypt_cost]]
        fail 401 "Invalid email or password."
    }
    if {![password_ok $user [dict get $fields password]] || ![dict get $user verified]} {fail 401 "Invalid email or password."}
    save_user $store $user {}
    set kind [expr {[dict get $user mfa_secret] eq {} ? "auth" : "two-factor"}]
    dict set result token [rotate $store $row $kind [dict get $user id]]
    dict set result view [expr {$kind eq "auth" ? "account" : "two-factor"}]
    return $result
}

proc ::web::user::action_forgot {config row fields} {
    set store [dict get $config -store]
    set uid [dict get $row uid]
    set result [dict create message {} debug_code {} delivery {}]
    set address [email [dict get $fields email]]
    set user [one $store web_user_users [dict create email_key [tag $store $address email]]]
    set code [random_token]
    set uid {}
    if {$user ne {} && [dict get $user verified]} {
        set uid [dict get $user id]
        dict set result delivery [list reset $address $code]
        dict set result debug_code $code
    }
    dict set result token [rotate $store $row reset $uid $code]
    dict set result view reset
    dict set result message {If the account exists, use the password reset code sent to your email.}
    return $result
}

proc ::web::user::action_reset {config row fields} {
    set store [dict get $config -store]
    set uid [dict get $row uid]
    set result [dict create message {} debug_code {} delivery {}]
    check_code $store $row reset [dict get $fields code]
    set user [user_by_id $store $uid]
    if {$user eq {}} {fail 400 "Invalid or expired code."}
    set hash [password_hash [dict get $fields password] [dict get $store -config]]
    save_user $store $user [dict create password $hash]
    # Reset does not remove MFA and never signs the browser in automatically.
    revoke $store $uid
    dict set result token [new_session $store]
    dict set result view login
    dict set result message {Password changed. Sign in again.}
    return $result
}

proc ::web::user::action_two_factor {config row fields} {
    set store [dict get $config -store]
    set uid [dict get $row uid]
    set result [dict create message {} debug_code {} delivery {}]
    if {[dict get $row kind] ne "two-factor"} {fail 401 "Sign in with your password first."}
    set user [user_by_id $store $uid]
    if {$user eq {} || [dict get $user mfa_secret] eq {}} {fail 401 "Sign in again."}
    set secret [unseal $store [dict get $user mfa_secret] [list mfa $uid]]
    set step [totp_step $store $secret [dict get $fields code] [dict get $user last_step]]
    if {$step < 0} {fail 401 "Invalid or already used authenticator code."}
    save_user $store $user [dict create last_step $step]
    dict set result token [rotate $store $row auth $uid]
    dict set result view account
    return $result
}

proc ::web::user::action_two_factor_setup {config row fields} {
    set store [dict get $config -store]
    set uid [dict get $row uid]
    set result [dict create message {} debug_code {} delivery {}]
    set user [require_user $store $row]
    if {[dict get $user mfa_secret] ne {}} {fail 409 "Two-factor authentication is already enabled."}
    if {[dict get $fields operation] eq "begin"} {
        if {![password_ok $user [dict get $fields password]]} {fail 401 "Invalid password."}
        set secret [string trimright [::tmfa::base32_encode [::twebserver::random_bytes 20]] =]
        update $store web_user_sessions [dict create id [dict get $row id]] \
            [dict create pending_secret [seal $store $secret [list mfa $uid]] expires [expr {[clock seconds] + [property $store challenge_ttl]}]]
        dict set result token {}
        dict set result view two-factor/setup
    } elseif {[dict get $fields operation] eq "confirm"} {
        if {[dict get $row pending_secret] eq {}} {fail 400 "Start authenticator setup first."}
        set secret [unseal $store [dict get $row pending_secret] [list mfa $uid]]
        set step [totp_step $store $secret [dict get $fields code] -1]
        if {$step < 0} {fail 401 "Invalid authenticator code."}
        save_user $store $user [dict create mfa_secret [dict get $row pending_secret] last_step $step]
        revoke $store $uid
        dict set result token [new_session $store auth $uid]
        dict set result view account
        dict set result message {Two-factor authentication enabled. Other sessions were signed out.}
    } else {fail 400 "Unknown setup operation."}
    return $result
}

proc ::web::user::action_two_factor_disable {config row fields} {
    set store [dict get $config -store]
    set uid [dict get $row uid]
    set result [dict create message {} debug_code {} delivery {}]
    set user [require_user $store $row]
    if {![password_ok $user [dict get $fields password]] || [dict get $user mfa_secret] eq {}} {fail 401 "Invalid credentials."}
    set secret [unseal $store [dict get $user mfa_secret] [list mfa $uid]]
    if {[totp_step $store $secret [dict get $fields code] [dict get $user last_step]] < 0} {fail 401 "Invalid or already used authenticator code."}
    save_user $store $user {mfa_secret {} last_step -1}
    revoke $store $uid
    dict set result token [new_session $store auth $uid]
    dict set result view account
    dict set result message {Two-factor authentication disabled. Other sessions were signed out.}
    return $result
}

proc ::web::user::action_logout {config row fields} {
    set store [dict get $config -store]
    set uid [dict get $row uid]
    set result [dict create message {} debug_code {} delivery {}]
    dict set result token [rotate $store $row anon]
    dict set result view login
    dict set result message {You have signed out.}
    return $result
}

proc ::web::user::require_user {store row} {
    set user [authenticated $store $row]
    if {$user eq {}} {fail 401 "Sign in first."}
    return $user
}
proc ::web::user::check_code {store row kind code} {
    if {[dict get $row kind] ne $kind || [dict get $row uid] eq {} ||
        ![verify_tag $store [dict get $row code_tag] $code [list code [dict get $row id]]]} {
        fail 400 "Invalid or expired code."
    }
}
