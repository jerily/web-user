#
# Copyright Jerily LTD. All Rights Reserved.
# SPDX-FileCopyrightText: 2026 Neofytos Dimitriou (neo@jerily.cy)
# SPDX-License-Identifier: MIT.
#

# Return a structured account HTTP error.
proc ::web::user::fail {status message} {return -code error -errorcode [list WEB USER $status] $message}
# Build an uncached response with account security headers.
proc ::web::user::response {status body {type {text/html; charset=utf-8}}} {
    # no-referrer makes browsers send Origin: null on form POSTs, which fails
    # our origin check. same-origin preserves it without sending external referrers.
    dict create statusCode $status body $body headers [dict create content-type $type \
        cache-control no-store x-content-type-options nosniff referrer-policy same-origin \
        content-security-policy {default-src 'self'; style-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'}]
}
# Read a request header without case sensitivity.
proc ::web::user::header {request name} {
    if {[dict exists $request headers]} {
        dict for {key value} [dict get $request headers] {if {[string equal -nocase $key $name]} {return $value}}
    }
    return {}
}
# Read and verify the account cookie.
proc ::web::user::cookie_token {config request} {
    ::tsession::cookie::read [dict get $config -session-cookie] $request
}
# Set persistence only after authentication, bounded by the stored expiry.
proc ::web::user::set_cookie {config response token} {
    set issued [::tsession::cookie::issue [dict get $config -session-cookie] {} $token]
    set cookie [dict get $issued headers Set-Cookie]
    set row [session [dict get $config -store] $token]
    if {$row ne {} && [dict get $row kind] eq "auth" && [session_persistent $row]} {
        append cookie "; Max-Age=[expr {max(0, [dict get $row expires] - [clock seconds])}]"
    }
    ::twebserver::add_header $response Set-Cookie $cookie
}
# Derive the session-bound CSRF token.
proc ::web::user::csrf_token {config token} {tag [dict get $config -store] $token csrf}
# Public callbacks for hosts and mounted content packages.
proc ::web::user::current_user {config request {context {}}} {
    set store [dict get $config -store]
    set user [authenticated $store [session $store [cookie_token $config $request]]]
    if {$user eq {}} {return {}}
    record_visit $store $user
    public_user $store $user
}
# Allow a host action only for an authenticated account.
proc ::web::user::authorize {config request context action path} {expr {[current_user $config $request $context] ne {}}}
# Bind a named permission to the generic wiki/blog authorization callback.
# Read grants on every call so revocation also applies to open editor forms.
proc ::web::user::authorize_permission {config permission request context action path} {
    set user [current_user $config $request $context]
    expr {$user ne {} && [has_permission [dict get $config -store] [dict get $user id] $permission]}
}
# Issue or validate a session-bound CSRF token and origin.
proc ::web::user::csrf {config action request context submitted} {
    set token [cookie_token $config $request]
    if {[session [dict get $config -store] $token] eq {}} {return [expr {$action eq "issue" ? "" : 0}]}
    if {$action eq "issue"} {return [csrf_token $config $token]}
    set expectedOrigin [dict get $config -config origin]
    set host [header $request host]
    # LOCAL browsers may use either loopback name and a custom listening port.
    # Still require the submitted Origin to match that request's host and port.
    if {[dict get $config -store -env] eq "LOCAL" &&
        [regexp -nocase {^(localhost|127\.0\.0\.1|\[::1\])(:[0-9]{1,5})?$} $host]} {
        set expectedOrigin [lindex [split $expectedOrigin :] 0]://[string tolower $host]
    }
    expr {[verify_tag [dict get $config -store] $submitted $token csrf] &&
        ([header $request origin] eq {} || [header $request origin] eq $expectedOrigin)}
}
# Decode form text with strict percent and UTF-8 validation.
proc ::web::user::decode {value} {
    set value [string map {+ { }} $value]
    set bytes {}
    for {set i 0} {$i < [string length $value]} {incr i} {
        set character [string index $value $i]
        if {$character eq "%"} {
            set hex [string range $value [expr {$i+1}] [expr {$i+2}]]
            if {![regexp {^[a-fA-F0-9]{2}$} $hex]} {fail 400 "Invalid percent encoding."}
            append bytes [binary format H2 $hex]
            incr i 2
        } else {append bytes [encoding convertto utf-8 $character]}
    }
    if {[catch {encoding convertfrom utf-8 $bytes} text] || [encoding convertto utf-8 $text] ne $bytes || [string first \x00 $text] >= 0} {
        fail 400 "Invalid UTF-8 form."
    }
    return $text
}
# Parse a bounded URL-encoded body and reject duplicate fields.
proc ::web::user::form {request {maximum 32768}} {
    if {[string tolower [string trim [lindex [split [header $request content-type] {;}] 0]]] ne "application/x-www-form-urlencoded"} {fail 415 "Use URL-encoded form data."}
    if {![dict exists $request body]} {fail 400 "Missing form body."}
    set body [dict get $request body]
    if {[string length $body] > $maximum} {fail 413 "Form too large."}
    if {[dict exists $request isBase64Encoded] && [dict get $request isBase64Encoded]} {
        if {[catch {binary decode base64 -strict $body} body]} {fail 400 "Invalid body."}
    }
    set fields {}
    foreach pair [split $body &] {
        set at [string first = $pair]
        if {$at < 1} {fail 400 "Invalid form field."}
        set key [decode [string range $pair 0 [expr {$at-1}]]]
        if {[dict exists $fields $key]} {fail 400 "Duplicate form field."}
        dict set fields $key [decode [string range $pair [expr {$at+1}] end]]
    }
    return $fields
}
# Encode ordinary fields as explicit JSON strings.
proc ::web::user::text_fields {values} {
    set result {}
    dict for {key value} $values {dict set result $key [list S $value]}
    return $result
}
# Read a UTF-8 resource and always close its channel.
proc ::web::user::read_text {filename} {
    set f [open $filename r]
    try {fconfigure $f -encoding utf-8; read $f} finally {close $f}
}
# Render the selected form with escaped account data.
proc ::web::user::render {config view token {extra {}}} {
    set store [dict get $config -store]
    set row [session $store $token]
    set user [authenticated $store $row]
    set fields [dict merge [dict create title [string totitle [string map {- { } / { }} $view]] \
        view $view prefix [dict get $config -prefix] brand [dict get $config -config title] \
        csrf [csrf_token $config $token] message {} debug_code {} email {} first_name {} last_name {} display_name {} username {} qr {} secret {} captcha_png {} captcha_id {} return_query {}] $extra]
    set usernameConflict 0
    if {[dict exists $extra username_conflict]} {set usernameConflict [dict get $extra username_conflict]}
    set verified 0
    set enabled 0
    if {$user ne {}} {
        set public [public_user $store $user]
        foreach key {email first_name last_name display_name username} {dict set fields $key [dict get $public $key]}
        if {$view eq "profile"} {
            dict set fields display_name [dict get [profile_names $store [dict get $user id]] display_name]
            foreach key {first_name last_name display_name username} {
                if {[dict exists $extra $key]} {dict set fields $key [dict get $extra $key]}
            }
        }
        set verified [dict get $public email_verified]
        set enabled [dict get $public mfa_enabled]
    }
    if {$view in {account profile change-password close-account two-factor/setup two-factor/disable}} {require_user $store $row}
    if {$view eq "two-factor/setup" && [dict get $row pending_secret] ne {}} {
        set secret [unseal $store [dict get $row pending_secret] [list mfa [dict get $user id]]]
        set uri [::tmfa::keyuri $secret totp [dict get $fields email] -issuer [dict get $config -config issuer] {*}[totp_options $store]]
        dict set fields qr [::tqrcodegen::encode_to_svg $uri]
        dict set fields secret $secret
        if {[dict get $store -env] eq "LOCAL"} {dict set fields debug_code [totp_code $store $secret]}
    }
    if {$view eq "two-factor" && $row ne {} && [dict get $row kind] eq "two-factor" && [dict get $store -env] eq "LOCAL"} {
        set pending [user_by_id $store [dict get $row uid]]
        if {$pending ne {} && [dict get $pending mfa_secret] ne {}} {
            dict set fields debug_code [totp_code $store [unseal $store [dict get $pending mfa_secret] [list mfa [dict get $pending id]]]]
        }
    }
    if {$view eq "two-factor/disable" && $user ne {} && $enabled && [dict get $store -env] eq "LOCAL"} {
        dict set fields debug_code [totp_code $store [unseal $store [dict get $user mfa_secret] [list mfa [dict get $user id]]]]
    }
    if {[dict get $store -env] ne "LOCAL"} {dict set fields debug_code {}}
    dict set fields password_min_length [property $store password_min_length]
    dict set fields captcha_length [property $store captcha_length]
    dict set fields totp_digits [property $store totp_digits]
    set context [dict merge [dict get $config -config properties] [text_fields $fields]]
    foreach key {collect_names collect_display_name collect_username} {
        dict set context $key [list BOOL [property $store $key]]
    }
    dict set context collect_profile [list BOOL [expr {[property $store collect_names] || [property $store collect_display_name] || [property $store collect_username]}]]
    dict set context captcha_letters [list BOOL [property $store captcha_letters]]
    dict set context username_conflict [list BOOL $usernameConflict]
    dict set context reload_form [list BOOL [expr {[dict exists $extra reload_form] && [dict get $extra reload_form]}]]
    dict set context stay_signed_in [list BOOL [expr {[dict exists $extra stay_signed_in] && [dict get $extra stay_signed_in] eq "1"}]]
    dict set context email_verified [list BOOL $verified]
    dict set context verification_emails_enabled [list BOOL [property $store verification_emails_enabled]]
    dict set context mfa_enabled [list BOOL $enabled]
    dict set context signed_in [list BOOL [expr {$user ne {}}]]
    dict set context can_manage_users [list BOOL [expr {$user ne {} && [has_permission $store [dict get $user id] users.manage]}]]
    dict set context admin_view {BOOL 0}
    dict set context google_enabled [list BOOL [dict get $config -config google_enabled]]
    dict set context password_enabled [list BOOL [expr {$user eq {} || [has_password $user]}]]
    dict set context google_linked [list BOOL [expr {$user ne {} && [google_linked $store [dict get $user id]]}]]
    set templates [dict get $config -templates]
    response 200 [::jinja2::render [dict get $templates form.html.jinja] \
        [::tjson::typed_to_json [list M $context]] -templates $templates -path form.html.jinja]
}
# Keep expected account errors inside a usable form, without replaying secrets.
proc ::web::user::form_error {config view token context fields message status detail needsCaptcha} {
    set store [dict get $config -store]
    set row [session $store $token]
    set kind [expr {$row eq {} ? "" : [dict get $row kind]}]
    if {$view eq "logout"} {set view account}
    if {$view eq "resend-verification"} {set view [expr {$kind eq "auth" ? "account" : "verify"}]}
    if {$view in {account profile change-password close-account two-factor/setup two-factor/disable} &&
        [authenticated $store $row] eq {}} {
        if {![dict exists $context return_to] || [dict get $context return_to] eq {}} {
            dict set context return_to [dict get $config -prefix]/[expr {$view eq "account" ? "" : $view}]
        }
        set view login
    }
    # Expired challenges must restart their flow instead of offering a dead form.
    if {$view eq "two-factor" && $kind ne "two-factor"} {set view login}
    if {$view eq "verify" && $kind ni {verify verify-email}} {set view register}
    if {$view eq "reset" && $kind ne "reset"} {set view forgot}
    if {$row eq {}} {
        set token {}
        if {$status != 429} {
            try {
                throttle $store [list browse [peer $context]] [property $store browse_limit]
                set token [new_session $store]
            } trap {WEB USER} {message opts} {
                set status [lindex [dict get $opts -errorcode] 2]
            }
        }
    }
    set extra [redisplay_fields $fields $message]
    if {$status == 409 && $detail eq "USERNAME" && $view eq "verify"} {
        dict set extra username_conflict 1
    }
    if {$status == 429 || $token eq {}} {
        dict set extra reload_form 1
        set needsCaptcha 0
    }
    try {
        return [form_response $config $view $token $context $extra $status $needsCaptcha]
    } trap {WEB USER} {message opts} {
        # A CAPTCHA issuance limit must also stay HTML, without another issuance.
        dict set extra message $message
        dict set extra reload_form 1
        return [form_response $config $view $token $context $extra [lindex [dict get $opts -errorcode] 2] 0]
    }
}
# Shared request guard; concrete endpoints supply their own action procedure.
proc ::web::user::handle {config view handler challenge request context} {
    set token {}
    set fields {}
    try {
        set store [dict get $config -store]
        set token [cookie_token $config $request]
        set row [session $store $token]
        record_visit $store [authenticated $store $row]
        set returnTo [requested_return_to $request]
        dict set context return_to $returnTo
        if {[dict get $request method] ne "POST"} {
            if {$view in {account profile change-password close-account two-factor/setup two-factor/disable} &&
                [authenticated $store $row] eq {}} {
                return [sign_in_redirect $config $request]
            }
            if {$returnTo ne {} && $view in {login register} && [authenticated $store $row] ne {}} {
                return [redirect $returnTo]
            }
            if {$row eq {}} {
                # Avoid unbounded anonymous-session creation from one peer.
                throttle $store [list browse [peer $context]] [property $store browse_limit]
                set token [new_session $store]
            }
            return [form_response $config $view $token $context]
        }
        set fields [form $request [property $store form_max_bytes]]
        if {$row eq {} || ![dict exists $fields csrf] || ![csrf $config verify $request $context [dict get $fields csrf]]} {fail 403 "Invalid CSRF token. Reload the form."}
        set operation [dict get $config -operations $view]
        set current [authenticated $store $row]
        if {$current ne {} && ![has_password $current] && $view in {change-password close-account two-factor/setup two-factor/disable}} {
            set operation [passwordless_operation $operation $view]
        }
        validate_form $request $fields $operation
        throttle $store [list post [peer $context]] [property $store post_limit]
        if {[dict exists $fields email]} {throttle $store [list $view [email [dict get $fields email]]] [property $store account_limit]}
        if {[dict get $row uid] ne {}} {throttle $store [list $view [dict get $row uid]] [property $store account_limit]}
        if {$view in {verify resend-verification}} {
            set emailKey [verification_email_key $store $row]
            if {$emailKey ne {}} {
                throttle $store [list verification $emailKey] [property $store challenge_limit]
                if {$view eq "resend-verification"} {
                    set cooldown $store
                    dict set cooldown -config throttle_window [property $store resend_cooldown]
                    throttle $cooldown [list resend $emailKey] 1
                }
            }
        }
        # Attempt counts commit independently, including unsuccessful checks.
        if {$challenge || ($view eq "two-factor/setup" && [dict get $fields operation] eq "confirm")} {
            throttle $store [list challenge [dict get $row id]] [property $store challenge_limit]
        }
        if {[captcha_required $config $view $context] && ![check_form_captcha $config $view $row $fields]} {
            return [form_response $config $view $token $context \
                [redisplay_fields $fields {Enter the characters in the new image. The previous answer was missing, incorrect, or expired.}] 400 1]
        }
        db_transaction [dict get $store -connection] {
            set fresh [session $store $token]
            if {$fresh eq {}} {fail 401 "Session expired. Reload the form."}
            set passwordCheck [expr {$view eq "login"}]
            set result [{*}$handler $config $fresh $fields]
        }
        if {[dict get $result token] ne {}} {set token [dict get $result token]}
        deliver_after_commit $config [dict get $result delivery]
        if {$returnTo ne {} && $view in {login register verify two-factor} &&
            [authenticated $store [session $store $token]] ne {}} {
            return [set_cookie $config [redirect $returnTo] $token]
        }
        set extra [dict create message [dict get $result message] debug_code [dict get $result debug_code]]
        return [form_response $config [dict get $result view] $token $context $extra]
    } trap {WEB USER} {message opts} {
        set status [lindex [dict get $opts -errorcode] 2]
        set needsCaptcha -1
        if {$view eq "login" && $status == 401 && [info exists passwordCheck] && $passwordCheck} {
            set needsCaptcha 0
            if {[property $store login_captcha_after] > 0} {
                set failures [record_login_failure $config $context]
                set needsCaptcha [expr {$failures >= [property $store login_captcha_after] - 1}]
            }
        }
        return [form_error $config $view $token $context $fields $message $status \
            [lindex [dict get $opts -errorcode] 3] $needsCaptcha]
    }
}
# Read the trusted client IP from server context.
proc ::web::user::peer {context} {
    # Trusted server context only; do not trust X-Forwarded-For from the request.
    if {[dict exists $context addr]} {return [dict get $context addr]}
    return unknown
}

# Show the authenticated account overview.
proc ::web::user::account {config request context params} {
    handle $config account {} 0 $request $context
}

# Handle the register account route.
proc ::web::user::register {config request context params} {
    handle $config register ::web::user::action_register 0 $request $context
}

# Handle the verify account route.
proc ::web::user::verify {config request context params} {
    handle $config verify ::web::user::action_verify 1 $request $context
}

# Handle the login account route.
proc ::web::user::login {config request context params} {
    handle $config login ::web::user::action_login 0 $request $context
}

# Handle the forgot account route.
proc ::web::user::forgot {config request context params} {
    handle $config forgot ::web::user::action_forgot 0 $request $context
}

# Handle the reset account route.
proc ::web::user::reset {config request context params} {
    handle $config reset ::web::user::action_reset 1 $request $context
}

# Handle the change password account route.
proc ::web::user::change_password {config request context params} {
    handle $config change-password ::web::user::action_change_password 0 $request $context
}

# Confirm and close the authenticated account.
proc ::web::user::close_account {config request context params} {
    handle $config close-account ::web::user::action_close_account 0 $request $context
}

# Handle the two factor account route.
proc ::web::user::two_factor {config request context params} {
    handle $config two-factor ::web::user::action_two_factor 1 $request $context
}

# Handle the two factor setup account route.
proc ::web::user::two_factor_setup {config request context params} {
    handle $config two-factor/setup ::web::user::action_two_factor_setup 0 $request $context
}

# Handle the two factor disable account route.
proc ::web::user::two_factor_disable {config request context params} {
    handle $config two-factor/disable ::web::user::action_two_factor_disable 0 $request $context
}

# Handle the logout account route.
proc ::web::user::logout {config request context params} {
    handle $config logout ::web::user::action_logout 0 $request $context
}

# Handle the profile account route.
proc ::web::user::profile {config request context params} {
    handle $config profile ::web::user::action_profile 0 $request $context
}

# Resend a challenge for the current registration or signed-in account.
proc ::web::user::resend_verification {config request context params} {
    handle $config resend-verification ::web::user::action_resend_verification 0 $request $context
}
