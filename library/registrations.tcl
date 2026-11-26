#
# Copyright Jerily LTD. All Rights Reserved.
# SPDX-FileCopyrightText: 2026 Neofytos Dimitriou (neo@jerily.cy)
# SPDX-License-Identifier: MIT.
#

# Look up a live registration without treating it as an account.
proc ::web::user::registration {store id} {
    set row [one $store web_user_registrations [dict create id $id]]
    if {$row eq {} || [dict get $row expires] <= [clock seconds]} {return {}}
    return $row
}

# Resolve a verification request to its shared per-email attempt bucket.
proc ::web::user::verification_email_key {store row} {
    set kind [dict get $row kind]
    if {$kind eq "verify"} {
        set subject [registration $store [dict get $row uid]]
    } elseif {$kind in {verify-email auth}} {
        set subject [user_by_id $store [dict get $row uid]]
    } else {return {}}
    expr {$subject eq {} ? {} : [dict get $subject email_key]}
}

# Insert one permanent account, translating a competing email claim into a conflict.
proc ::web::user::insert_account {store values} {
    check_username $store [dict get $values username]
    if {[catch {
        db_transaction [dict get $store -connection] {insert $store web_user_users $values}
    } message opts]} {
        if {[one $store web_user_users [dict create email_key [dict get $values email_key]]] ne {}} {
            fail 409 "Registration was already completed. Sign in or recover your password."
        }
        check_username $store [dict get $values username]
        return -options $opts $message
    }
}

# Copy the selected registration's credentials into a newly activated account.
proc ::web::user::activate_registration {store pending verified} {
    set uid [dict get $pending id]
    set values [dict create id $uid active 1 verified $verified mfa_secret {} last_step -1 revision 0]
    foreach key {email_key email password username created_at} {dict set values $key [dict get $pending $key]}
    insert_account $store $values
    if {[dict get $pending first_name] ne {} || [dict get $pending display_name] ne {}} {
        insert $store web_user_profiles [dict create id $uid first_name [dict get $pending first_name] last_name [dict get $pending last_name] display_name [dict get $pending display_name]]
    }
    # The permanent email constraint serializes competing confirmations. A new
    # pending insert racing this cleanup cannot later replace the winning user.
    foreach other [rows $store web_user_registrations [dict create email_key [dict get $pending email_key]]] {
        set id [dict get $other id]
        remove $store web_user_registrations [dict create id $id]
        revoke $store $id
    }
    return $uid
}

# Save an independent registration, or activate it immediately under site policy.
proc ::web::user::action_register {config row fields} {
    set store [dict get $config -store]
    set names [name_fields $store $fields]
    set username [username_field $store $fields]
    check_username $store $username
    set address [email [dict get $fields email]]
    set hash [password_hash [dict get $fields password] [dict get $store -config]]
    set emailKey [email_key $store $address]
    set required [property $store email_verification_required]
    set send [expr {[property $store verification_emails_enabled] &&
        ([dict get $config -config email_enabled] || [property $store show_verification_codes])}]
    set result [dict create message {} debug_code {} delivery {} token {} view login]
    set uid {}
    set code [verification_code]
    if {[one $store web_user_users [dict create email_key $emailKey]] eq {}} {
        set uid user_[::ksuid::generate_ksuid]
        set pending [dict create id $uid email_key $emailKey email [seal $store $address [list email $uid]] \
            password [seal $store $hash [list password-hash $uid]] username $username first_name {} last_name {} display_name {} created_at [clock seconds] \
            expires [expr {[clock seconds] + [property $store code_ttl]}]]
        dict for {key value} $names {
            dict set pending $key [expr {$value eq {} ? {} : [seal $store $value [list profile $uid $key]]}]
        }
        if {$required} {
            insert $store web_user_registrations $pending
        } else {
            activate_registration $store $pending 0
        }
        if {$required || $send} {
            if {$send} {dict set result delivery [list verify $address $code]}
            dict set result debug_code $code
        }
    }
    if {$required || $send} {
        set kind [expr {$required ? "verify" : "verify-email"}]
        dict set result token [rotate $store $row $kind $uid $code]
        dict set result view verify
        dict set result message [expr {$required ?
            "If registration is available, use the verification code sent to your email." :
            "If registration is available, you can sign in now. You can also confirm your email with the code sent to you."}]
    } else {
        dict set result token [rotate $store $row anon]
        dict set result message {If registration is available, you can now sign in.}
    }
    return $result
}

proc ::web::user::verification_signs_in {config} {
    dict get $config -config login_after_email_verification
}

# Confirm exactly one registration, or mark an existing active account's email verified.
proc ::web::user::action_verify {config row fields} {
    set store [dict get $config -store]
    set uid [dict get $row uid]
    set kind [dict get $row kind]
    if {$kind ni {verify verify-email}} {fail 400 "Invalid or expired code."}
    check_code $store $row $kind [dict get $fields code]
    if {$kind eq "verify"} {
        set pending [registration $store $uid]
        if {$pending eq {}} {fail 400 "Invalid or expired code."}
        if {[property $store collect_username] && [dict exists $fields username]} {
            dict set pending username [username_field $store $fields]
        }
        activate_registration $store $pending 1
        # Activation revoked every pending session for this registration.
        set row {}
    }
    if {[verification_signs_in $config]} {
        return [sign_in_with_verified_email $store $row [user_by_id $store $uid]]
    }
    if {$kind eq "verify-email"} {
        set user [user_by_id $store $uid]
        if {$user eq {} || ![dict get $user active]} {fail 400 "Invalid or expired code."}
        save_user $store $user {verified 1}
    }
    dict create token [rotate $store $row anon] view login message {Email verified. You can now sign in.} debug_code {} delivery {}
}

# Replace only this browser's verification code, preserving its chosen credentials.
proc ::web::user::action_resend_verification {config row fields} {
    set store [dict get $config -store]
    if {![property $store verification_emails_enabled]} {fail 403 "Verification emails are disabled."}
    set uid [dict get $row uid]
    set kind [dict get $row kind]
    if {$kind eq "verify"} {
        set subject [registration $store $uid]
        if {$subject ne {}} {
            update $store web_user_registrations [dict create id $uid] \
                [dict create expires [expr {[clock seconds] + [property $store code_ttl]}]]
        }
    } elseif {$kind in {verify-email auth}} {
        set subject [user_by_id $store $uid]
        if {$subject ne {} && (![dict get $subject active] || [dict get $subject verified])} {set subject {}}
        set kind verify-email
    } else {set subject {}}
    if {$subject eq {}} {fail 400 "Start registration again or sign in to verify your email."}
    set address [unseal $store [dict get $subject email] [list email $uid]]
    set code [verification_code]
    dict create token [rotate $store $row $kind $uid $code] view verify \
        message {A new verification code has been requested.} debug_code $code delivery [list verify $address $code]
}
