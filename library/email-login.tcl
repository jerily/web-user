# Email sign-in uses the same browser-bound SQL challenges as account recovery.
# Only keyed verifiers are stored; mail delivery happens after the transaction.
proc ::web::user::action_email_login {config row fields} {
    set store [dict get $config -store]
    set address [email [dict get $fields email]]
    set user [user_by_email $store $address]
    set code [verification_code]
    set uid {}
    set delivery {}
    if {$user eq {} || [dict get $user active]} {
        set uid [expr {$user eq {} ? "user_[::ksuid::generate_ksuid]" : [dict get $user id]}]
        set delivery [list login $address $code]
    }
    set persistent [expr {[dict exists $fields stay_signed_in] && [dict get $fields stay_signed_in] eq "1"}]
    set token [rotate $store $row email-login $uid $code $persistent]
    if {$user eq {}} {
        # Keep only an encrypted address in this browser's expiring challenge.
        # No account or profile exists until the code has been verified.
        set next [session $store $token]
        set address [seal $store $address [list email-login [dict get $next id]]]
        if {[::tsession::sql::update [dict get $store -sessions] [dict get $next id] \
            [dict create email_login_address $address]] != 1} {fail 409 "Session changed; request a new code."}
    }
    return [dict create token $token \
        view email-login/verify message {If this email can be used, a sign-in code is on its way. Enter it below in this browser.} \
        debug_code $code delivery $delivery]
}

proc ::web::user::email_mark_session {store token when {pending 0}} {
    request_mutating
    set row [session $store $token]
    if {[::tsession::sql::update [dict get $store -sessions] [dict get $row id] \
        [dict create email_verified_at $when email_login_pending $pending]] != 1} {
        fail 409 "Session changed; sign in again."
    }
}

proc ::web::user::action_email_login_verify {config row fields} {
    set store [dict get $config -store]
    check_code $store $row email-login [dict get $fields code]
    set user [user_by_id $store [dict get $row uid]]
    if {[dict exists $row email_login_address]} {
        set address [unseal $store [dict get $row email_login_address] [list email-login [dict get $row id]]]
        # Another browser may have registered this address since the code was
        # requested. Preserve that account's credentials, status and MFA.
        set user [user_by_email $store $address]
        if {$user eq {}} {
            set uid [dict get $row uid]
            set user [dict create id $uid email_key [email_key $store $address] \
                email [seal $store $address [list email $uid]] password {} username {} \
                verified 1 active 1 mfa_secret {} last_step -1 revision 0 created_at [clock seconds]]
            insert_account $store $user
            # Never inherit a password or profile from an unconfirmed signup.
            foreach pending [rows $store web_user_registrations [dict create email_key [dict get $user email_key]]] {
                set pendingId [dict get $pending id]
                remove $store web_user_registrations [dict create id $pendingId]
                revoke $store $pendingId
            }
        }
    }
    if {$user eq {} || ![dict get $user active]} {
        fail 400 "Invalid or expired code."
    }
    set kind [expr {[dict get $user mfa_secret] eq {} ? "auth" : "two-factor"}]
    # A valid email code proves ownership; an enrolled authenticator is still required.
    set changes {verified 1}
    if {$kind eq "auth"} {
        set now [clock seconds]
        set changes [dict merge $changes [dict create last_login_at $now last_seen_at $now last_email_login_at $now]]
    }
    save_user $store $user $changes
    set token [rotate $store $row $kind [dict get $user id] {} [session_persistent $row]]
    email_mark_session $store $token [clock seconds] [expr {$kind eq "two-factor"}]
    return [dict create token $token view [expr {$kind eq "auth" ? "account" : "two-factor"}] \
        message {} debug_code {} delivery {}]
}

proc ::web::user::email_login {config request context params} {
    handle $config email-login ::web::user::action_email_login 0 $request $context
}
proc ::web::user::email_login_verify {config request context params} {
    handle $config email-login/verify ::web::user::action_email_login_verify 1 $request $context
}
