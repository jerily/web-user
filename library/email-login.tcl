# Email sign-in uses the same browser-bound SQL challenges as account recovery.
# Only keyed verifiers are stored; mail delivery happens after the transaction.
proc ::web::user::action_email_login {config row fields} {
    set store [dict get $config -store]
    set address [email [dict get $fields email]]
    set user [user_by_email $store $address]
    set code [verification_code]
    set uid {}
    set delivery {}
    if {$user ne {} && [dict get $user active] && [dict get $user verified]} {
        set uid [dict get $user id]
        set delivery [list login $address $code]
    }
    set persistent [expr {[dict exists $fields stay_signed_in] && [dict get $fields stay_signed_in] eq "1"}]
    return [dict create token [rotate $store $row email-login $uid $code $persistent] \
        view email-login/verify message {If this email belongs to an active, verified account, a sign-in code is on its way. Enter it below in this browser.} \
        debug_code $code delivery $delivery]
}

proc ::web::user::action_email_login_verify {config row fields} {
    set store [dict get $config -store]
    check_code $store $row email-login [dict get $fields code]
    set user [user_by_id $store [dict get $row uid]]
    if {$user eq {} || ![dict get $user active] || ![dict get $user verified]} {
        fail 400 "Invalid or expired code."
    }
    set kind [expr {[dict get $user mfa_secret] eq {} ? "auth" : "two-factor"}]
    set changes {}
    if {$kind eq "auth"} {
        set now [clock seconds]
        set changes [dict create last_login_at $now last_seen_at $now last_email_login_at $now]
    }
    save_user $store $user $changes
    set token [rotate $store $row $kind [dict get $user id] {} [session_persistent $row]]
    if {$kind eq "two-factor"} {
        set next [session $store $token]
        if {[::tsession::sql::update [dict get $store -sessions] [dict get $next id] {email_login_pending 1}] != 1} {
            fail 409 "Session changed; retry the request."
        }
    }
    return [dict create token $token view [expr {$kind eq "auth" ? "account" : "two-factor"}] \
        message {} debug_code {} delivery {}]
}

proc ::web::user::email_login {config request context params} {
    handle $config email-login ::web::user::action_email_login 0 $request $context
}
proc ::web::user::email_login_verify {config request context params} {
    handle $config email-login/verify ::web::user::action_email_login_verify 1 $request $context
}
