#
# Copyright Jerily LTD. All Rights Reserved.
# SPDX-FileCopyrightText: 2026 Neofytos Dimitriou (neo@jerily.cy)
# SPDX-License-Identifier: MIT.
#

# Select the SQL session backend for the current environment.
proc ::web::user::session_backend {} {
    set backend [expr {[environment] eq "LOCAL" ? "sqlite" : "postgres"}]
    package require tsession-$backend 1.0.1
    return ::tsession::$backend
}
# Resolve a browser token to a live SQL session.
proc ::web::user::session {store token} {
    if {![regexp {^[a-f0-9]{64}$} $token]} {return {}}
    ::tsession::sql::get [dict get $store -sessions] [tag $store $token session]
}
# Read the stored opt-in, treating older sessions as browser-session logins.
proc ::web::user::session_persistent {row} {
    expr {[dict exists $row stay_signed_in] && [dict get $row stay_signed_in]}
}
# Persist a fresh session; only authenticated opt-ins receive the longer lifetime.
proc ::web::user::new_session {store {kind anon} {uid {}} {code {}} {staySignedIn 0}} {
    set token [random_token]
    set id [tag $store $token session]
    set ttl [property $store [expr {$kind eq "auth" ? "session_ttl" : ($kind in {verify verify-email reset} ? "code_ttl" : "challenge_ttl")}]]
    set staySignedIn [expr {$kind in {auth two-factor} && $staySignedIn}]
    if {$kind eq "auth" && $staySignedIn} {set ttl [property $store persistent_session_ttl]}
    set codeTag [expr {$code eq {} ? {} : [tag $store $code [list code $id]]}]
    ::tsession::sql::insert [dict get $store -sessions] $id [dict create uid $uid kind $kind \
        expires [expr {[clock seconds] + $ttl}] code_tag $codeTag pending_secret {} stay_signed_in $staySignedIn] $uid
    return $token
}
# Delete a challenge exactly once or report a concurrent completion.
proc ::web::user::consume {store row} {
    if {[::tsession::sql::delete [dict get $store -sessions] [dict get $row id]] != 1} {fail 409 "This request was already completed."}
}
# Replace the current session with fresh credentials.
proc ::web::user::rotate {store row kind {uid {}} {code {}} {staySignedIn 0}} {
    if {$row ne {}} {consume $store $row}
    new_session $store $kind $uid $code $staySignedIn
}
# Revoke all sessions and challenges associated with a subject.
proc ::web::user::revoke {store uid} {::tsession::sql::revoke [dict get $store -sessions] $uid}
# Return decrypted account fields for the authenticated browser.
proc ::web::user::public_user {store user} {
    set names [profile_names $store [dict get $user id]]
    set displayName [profile_display_name $names]
    dict merge $names [dict create display_name $displayName username [dict get $user username] id [dict get $user id] email [unseal $store [dict get $user email] [list email [dict get $user id]]] \
        email_verified [dict get $user verified] mfa_enabled [expr {[dict get $user mfa_secret] ne {}}]]
}
# Resolve an active account only from an authenticated session.
proc ::web::user::authenticated {store row} {
    if {$row eq {} || [dict get $row kind] ne "auth"} {return {}}
    set user [user_by_id $store [dict get $row uid]]
    if {$user eq {} || ![dict get $user active]} {return {}}
    return $user
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
    set where [dict create id $id]
    if {[one $store web_user_limits $where] eq {}} {
        if {[catch {insert $store web_user_limits [dict create id $id hits 0 expires $expires]} message opts]} {
            if {[one $store web_user_limits $where] eq {}} {return -options $opts $message}
        }
    }
    db_execute [dict get $store -connection] [db_where \
        [db_values [db_update web_user_limits] [dict create hits [db_add [db_col hits] [db_value 1 -type integer]]] -expressions] \
        [predicate $store $where]]
    dict get [one $store web_user_limits $where] hits
}
