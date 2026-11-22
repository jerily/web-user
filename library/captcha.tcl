#
# Copyright Jerily LTD. All Rights Reserved.
# SPDX-FileCopyrightText: 2026 Neofytos Dimitriou (neo@jerily.cy)
# SPDX-License-Identifier: MIT.
#

# Captchas bind to the tenant, mount, action and browser session. The server
# stores only the verifier in an expiring SQL session row, never credentials.
proc ::web::user::captcha_context {config view row} {
    list web-user [dict get $config -store -tenant] [dict get $config -prefix] $view [dict get $row id]
}
# Reuse the existing indexed SQL limits table. Only login forms/checks read
# this counter; only failed password checks increment it. Neither successful
# logins nor GET requests increment it. Counts survive worker restarts.
proc ::web::user::login_counter_bucket {config context} {
    set store [dict get $config -store]
    set window [property $store login_captcha_window]
    set bucket [expr {[clock seconds] / $window}]
    set subject [list [dict get $config -prefix] [peer $context] $window $bucket]
    list [tag $store $subject login-failure] [expr {($bucket + 1) * $window}]
}
# Read the current IP failure count without incrementing it.
proc ::web::user::login_failures {config context} {
    set store [dict get $config -store]
    lassign [login_counter_bucket $config $context] id expires
    set row [one $store web_user_limits [dict create id $id]]
    expr {$row eq {} ? 0 : [dict get $row hits]}
}
# Persist one failed password check outside the account transaction.
proc ::web::user::record_login_failure {config context} {
    set store [dict get $config -store]
    lassign [login_counter_bucket $config $context] id expires
    increment_limit $store $id $expires
}
# Evaluate the CAPTCHA policy for this form and client IP.
proc ::web::user::captcha_required {config view context} {
    set store [dict get $config -store]
    if {$view in {register forgot email-login}} {return [property $store registration_captcha]}
    if {$view ne "login"} {return 0}
    set after [property $store login_captcha_after]
    if {$after == 1} {return 1}
    expr {$after > 0 && [login_failures $config $context] >= $after - 1}
}
proc ::web::user::honeypot_required {store view} {
    expr {$view in {register forgot email-login login} && [property $store registration_honeypot]}
}

# Derive the storage key for a session-bound CAPTCHA.
proc ::web::user::captcha_key {store context id} {tag $store $id [list form-captcha $context]}
# Persist an expiring verifier and return the browser image and ID.
proc ::web::user::issue_form_captcha {config view token context} {
    set store [dict get $config -store]
    set row [session $store $token]
    if {$row eq {}} {fail 401 "Session expired. Reload the form."}
    throttle $store [list captcha-image [dict get $config -prefix] [peer $context]] [property $store browse_limit]
    set binding [captcha_context $config $view $row]
    set ttl [expr {min([property $store captcha_ttl], [dict get $row expires] - [clock seconds])}]
    if {$ttl < 1} {fail 401 "Session expired. Reload the form."}
    set challenge [::tcaptcha::create -mac [dict get $store -mac] -context $binding -ttl $ttl \
        -length [property $store captcha_length] -letters [property $store captcha_letters]]
    set state [dict get $challenge state]
    set id [dict get $state id]
    ::tsession::sql::insert [dict get $store -sessions] [captcha_key $store $binding $id] \
        [dict create expires [dict get $state expires] state $state]
    dict create captcha_id $id captcha_png [binary encode base64 -maxlen 0 [dict get $challenge png]]
}
# Consume in its own transaction BEFORE password checking or account writes.
# A wrong password or later validation error must not restore a used CAPTCHA.
proc ::web::user::check_form_captcha {config view row fields} {
    set store [dict get $config -store]
    throttle $store [list form-captcha [dict get $config -prefix] $view [dict get $row id]] [property $store challenge_limit]
    if {![dict exists $fields captcha_id] || ![dict exists $fields captcha_answer] ||
        ![regexp {^[0-9a-f]{32}$} [dict get $fields captcha_id]]} {return 0}
    set binding [captcha_context $config $view $row]
    set key [captcha_key $store $binding [dict get $fields captcha_id]]
    set valid 0
    db_transaction [dict get $store -connection] {
        set saved [::tsession::sql::get [dict get $store -sessions] $key]
        if {$saved ne {} && [::tsession::sql::delete [dict get $store -sessions] $key] == 1} {
            set valid [::tcaptcha::verify [dict get $store -mac] $binding [dict get $saved state] [dict get $fields captcha_answer]]
        }
    }
    return $valid
}
# Preserve non-secret fields when a form has to be shown again. Passwords and
# CAPTCHA answers are never reflected into HTML or persisted in session state.
proc ::web::user::redisplay_fields {fields message} {
    set extra [dict create message $message]
    foreach name {email first_name last_name display_name username stay_signed_in} {
        if {[dict exists $fields $name]} {dict set extra $name [dict get $fields $name]}
    }
    return $extra
}
# Attach any required CAPTCHA and return the rendered form and cookie.
proc ::web::user::form_response {config view token context {extra {}} {status 200} {needsCaptcha -1}} {
    if {[dict exists $context return_to]} {
        dict set extra return_query [return_query [dict get $context return_to]]
    }
    if {$needsCaptcha < 0} {set needsCaptcha [captcha_required $config $view $context]}
    if {$needsCaptcha} {
        set extra [dict merge $extra [issue_form_captcha $config $view $token $context]]
    }
    set response [render $config $view $token $extra]
    dict set response statusCode $status
    if {$token eq {}} {return $response}
    set_cookie $config $response $token
}
