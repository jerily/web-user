proc ::web::user::session {store token} {
    if {![regexp {^[a-f0-9]{64}$} $token]} {return {}}
    set row [one $store web_user_sessions [dict create id [tag $store $token session]]]
    if {$row eq {} || [dict get $row expires] <= [clock seconds]} {return {}}
    return $row
}
proc ::web::user::new_session {store {kind anon} {uid {}} {code {}}} {
    set token [random_token]
    set id [tag $store $token session]
    set ttl [property $store [expr {$kind eq "auth" ? "session_ttl" : ($kind in {verify reset} ? "code_ttl" : "challenge_ttl")}]]
    set codeTag [expr {$code eq {} ? {} : [tag $store $code [list code $id]]}]
    insert $store web_user_sessions [dict create id $id uid $uid kind $kind \
        expires [expr {[clock seconds] + $ttl}] code_tag $codeTag attempts 0 pending_secret {}]
    return $token
}
proc ::web::user::consume {store row} {
    if {[remove $store web_user_sessions [dict create id [dict get $row id]]] != 1} {fail 409 "This request was already completed."}
}
proc ::web::user::rotate {store row kind {uid {}} {code {}}} {
    if {$row ne {}} {consume $store $row}
    new_session $store $kind $uid $code
}
proc ::web::user::revoke {store uid} {remove $store web_user_sessions [dict create uid $uid]}
proc ::web::user::public_user {store user} {
    set names [profile_names $store [dict get $user id]]
    set displayName [dict get $names first_name]
    if {$displayName eq {}} {set displayName Member}
    dict merge $names [dict create display_name $displayName id [dict get $user id] email [unseal $store [dict get $user email] [list email [dict get $user id]]] \
        mfa_enabled [expr {[dict get $user mfa_secret] ne {}}]]
}
proc ::web::user::authenticated {store row} {
    if {$row eq {} || [dict get $row kind] ne "auth"} {return {}}
    set user [user_by_id $store [dict get $row uid]]
    if {$user eq {} || ![dict get $user verified]} {return {}}
    return $user
}
# Persistent fixed windows survive process restarts. Count BEFORE the business transaction.
proc ::web::user::throttle {store subject maximum} {
    set window [property $store throttle_window]
    set bucket [expr {[clock seconds] / $window}]
    set id [tag $store [list $subject $bucket] limit]
    set where [dict create id $id]
    if {[one $store web_user_limits $where] eq {}} {
        if {[catch {insert $store web_user_limits [dict create id $id hits 0 expires [expr {($bucket + 1) * $window}]]} message opts]} {
            if {[one $store web_user_limits $where] eq {}} {return -options $opts $message}
        }
    }
    db_execute [dict get $store -connection] [db_where \
        [db_values [db_update web_user_limits] [dict create hits [db_add [db_col hits] [db_value 1 -type integer]]] -expressions] \
        [predicate $store $where]]
    if {[dict get [one $store web_user_limits $where] hits] > $maximum} {fail 429 "Too many attempts. Try again later."}
}
# TODO: deliver verification/reset messages by email. The default deliberately sends nothing.
# Hosts can supply -deliver {command prefix}; it receives purpose, email, code.
proc ::web::user::deliver {config purpose destination code} {
    if {[dict get $config -deliver] ne {}} {{*}[dict get $config -deliver] $purpose $destination $code}
}
