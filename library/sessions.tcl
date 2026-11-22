#
# Copyright Jerily LTD. All Rights Reserved.
# SPDX-FileCopyrightText: 2026 Neofytos Dimitriou (neo@jerily.cy)
# SPDX-License-Identifier: MIT.
#

# Resolve a browser token to a live SQL session.
proc ::web::user::session {store token} {
    if {![regexp {^[a-f0-9]{64}$} $token]} {return {}}
    set key [list session $store $token]
    if {[request_get $key row]} {
        if {$row eq {} || [dict get $row expires] > [clock seconds]} {return $row}
        request_invalidate
    }
    request_put $key [::tsession::sql::get [dict get $store -sessions] [tag $store $token session]]
}
# Read the stored opt-in, treating older sessions as browser-session logins.
proc ::web::user::session_persistent {row} {
    expr {[dict exists $row stay_signed_in] && [dict get $row stay_signed_in]}
}
# Persist a fresh session; only authenticated opt-ins receive the longer lifetime.
proc ::web::user::new_session {store {kind anon} {uid {}} {code {}} {staySignedIn 0}} {
    if {$kind ne "anon"} {request_mutating}
    set token [random_token]
    set id [tag $store $token session]
    set ttl [property $store [expr {$kind eq "auth" ? "session_ttl" : ($kind in {verify verify-email reset email-login} ? "code_ttl" : "challenge_ttl")}]]
    set staySignedIn [expr {$kind in {auth two-factor email-login} && $staySignedIn}]
    if {$kind eq "auth" && $staySignedIn} {set ttl [property $store persistent_session_ttl]}
    set codeTag [expr {$code eq {} ? {} : [tag $store $code [list code $id]]}]
    set row [dict create id $id uid $uid kind $kind \
        expires [expr {[clock seconds] + $ttl}] code_tag $codeTag pending_secret {} stay_signed_in $staySignedIn]
    ::tsession::sql::insert [dict get $store -sessions] $id $row $uid
    request_put [list session $store $token] $row
    return $token
}
# Delete a challenge exactly once or report a concurrent completion.
proc ::web::user::consume {store row} {
    request_mutating
    if {[::tsession::sql::delete [dict get $store -sessions] [dict get $row id]] != 1} {fail 409 "This request was already completed."}
}
# Replace the current session with fresh credentials.
proc ::web::user::rotate {store row kind {uid {}} {code {}} {staySignedIn 0}} {
    if {$row ne {}} {consume $store $row}
    new_session $store $kind $uid $code $staySignedIn
}
# Revoke all sessions and challenges associated with a subject.
proc ::web::user::revoke {store uid} {
    request_mutating
    ::tsession::sql::revoke [dict get $store -sessions] $uid
}
# Return decrypted account fields for the authenticated browser.
proc ::web::user::public_user {store user args} {
    if {[llength $args] > 1} {error "expected an optional profile row"}
    if {[llength $args]} {
        set names [profile_decode $store [dict get $user id] [lindex $args 0]]
    } else {set names [profile_names $store [dict get $user id]]}
    set displayName [profile_display_name $names]
    dict merge $names [dict create display_name $displayName username [dict get $user username] id [dict get $user id] email [unseal $store [dict get $user email] [list email [dict get $user id]]] \
        email_verified [dict get $user verified] mfa_enabled [expr {[dict get $user mfa_secret] ne {}}]]
}
# Resolve an active account only from an authenticated session.
proc ::web::user::authenticated {store row} {
    if {$row eq {} || [dict get $row kind] ne "auth"} {return {}}
    set key [list authenticated $store [dict get $row uid]]
    if {[request_get $key user]} {return $user}
    set user [user_by_id $store [dict get $row uid]]
    if {$user eq {} || ![dict get $user active]} {return [request_put $key {}]}
    return [request_put $key $user]
}
# Record HTTP activity at most once per minute across workers. The database
# condition also protects callers with a partial or stale user dictionary.
proc ::web::user::record_visit {store user} {
    if {$user eq {}} {return}
    set key [list record_visit $store [dict get $user id]]
    if {[request_get $key count]} {return $count}
    set now [clock seconds]
    if {[dict exists $user last_seen_at]} {
        set previous [dict get $user last_seen_at]
        if {[string is wideinteger -strict $previous] && $now - $previous < 60} {return}
    }
    set where [db_and [predicate $store [dict create id [dict get $user id] active 1]] \
        [db_le [db_col last_seen_at] [db_value [expr {$now - 60}] -type bigint]]]
    request_put $key [dict get [db_execute [dict get $store -connection] [db_where \
        [db_values [db_update web_user_users] [typed_values [dict create last_seen_at $now]] -expressions] $where]] rowcount]
}
# Persistent fixed windows survive process restarts. Count BEFORE the business transaction.
proc ::web::user::throttle {store subject maximum} {
    set window [property $store throttle_window]
    set bucket [expr {[clock seconds] / $window}]
    set id [tag $store [list $subject $bucket] limit]
    if {[increment_limit $store $id [expr {($bucket + 1) * $window}]] > $maximum} {
        fail 429 "Too many attempts. Try again later."
    }
}
# Atomically increment a persistent counting bucket.
proc ::web::user::increment_limit {store id expires} {
    db_increment [dict get $store -connection] web_user_limits \
        [dict create tenant [dict get $store -tenant] id $id] hits \
        -initial [dict create expires $expires] -types {tenant text id text hits bigint expires bigint}
}
