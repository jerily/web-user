proc ::web::user::fail {status message} {return -code error -errorcode [list WEB USER $status] $message}
proc ::web::user::response {status body {type {text/html; charset=utf-8}}} {
    # no-referrer makes browsers send Origin: null on form POSTs, which fails
    # our origin check. same-origin preserves it without sending external referrers.
    dict create statusCode $status body $body headers [dict create content-type $type \
        cache-control no-store x-content-type-options nosniff referrer-policy same-origin \
        content-security-policy {default-src 'self'; style-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'}]
}
proc ::web::user::header {request name} {
    if {[dict exists $request headers]} {
        dict for {key value} [dict get $request headers] {if {[string equal -nocase $key $name]} {return $value}}
    }
    return {}
}
proc ::web::user::cookie_token {config request} {
    ::tsession::cookie::read [dict get $config -session-cookie] $request
}
proc ::web::user::set_cookie {config response token} {
    ::tsession::cookie::issue [dict get $config -session-cookie] $response $token
}
proc ::web::user::csrf_token {config token} {tag [dict get $config -store] $token csrf}
# Public callbacks for hosts and mounted content packages.
proc ::web::user::current_user {config request {context {}}} {
    set store [dict get $config -store]
    set user [authenticated $store [session $store [cookie_token $config $request]]]
    if {$user eq {}} {return {}}
    public_user $store $user
}
proc ::web::user::authorize {config request context action path} {expr {[current_user $config $request $context] ne {}}}
proc ::web::user::csrf {config action request context submitted} {
    set token [cookie_token $config $request]
    if {[session [dict get $config -store] $token] eq {}} {return [expr {$action eq "issue" ? "" : 0}]}
    if {$action eq "issue"} {return [csrf_token $config $token]}
    expr {[verify_tag [dict get $config -store] $submitted $token csrf] &&
        ([header $request origin] eq {} || [header $request origin] eq [dict get $config -config origin])}
}
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
proc ::web::user::text_fields {values} {
    set result {}
    dict for {key value} $values {dict set result $key [list S $value]}
    return $result
}
proc ::web::user::read_text {filename} {
    set f [open $filename r]
    try {fconfigure $f -encoding utf-8; read $f} finally {close $f}
}
proc ::web::user::render {config view token {extra {}}} {
    set store [dict get $config -store]
    set row [session $store $token]
    set user [authenticated $store $row]
    set fields [dict merge [dict create title [string totitle [string map {- { } / { }} $view]] \
        view $view prefix [dict get $config -prefix] brand [dict get $config -config title] \
        csrf [csrf_token $config $token] message {} debug_code {} email {} first_name {} last_name {} qr {} secret {}] $extra]
    set enabled 0
    if {$user ne {}} {
        set public [public_user $store $user]
        foreach key {email first_name last_name} {dict set fields $key [dict get $public $key]}
        set enabled [dict get $public mfa_enabled]
    }
    if {$view in {account profile change-password two-factor/setup two-factor/disable}} {require_user $store $row}
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
    dict set fields totp_digits [property $store totp_digits]
    set context [dict merge [dict get $config -config properties] [text_fields $fields]]
    dict set context collect_names [list BOOL [property $store collect_names]]
    dict set context mfa_enabled [list BOOL $enabled]
    dict set context signed_in [list BOOL [expr {$user ne {}}]]
    set templates [dict get $config -templates]
    response 200 [::jinja2::render [dict get $templates form.html.jinja] \
        [::tjson::typed_to_json [list M $context]] -templates $templates -path form.html.jinja]
}
# Shared request guard; concrete endpoints supply their own action procedure.
proc ::web::user::handle {config view handler challenge request context} {
    try {
        set store [dict get $config -store]
        set token [cookie_token $config $request]
        set row [session $store $token]
        if {[dict get $request method] ne "POST"} {
            if {$row eq {}} {
                # Avoid unbounded anonymous-session creation from one peer.
                throttle $store [list browse [peer $context]] [property $store browse_limit]
                set token [new_session $store]
            }
            return [set_cookie $config [render $config $view $token] $token]
        }
        set fields [form $request [property $store form_max_bytes]]
        if {$row eq {} || ![dict exists $fields csrf] || ![csrf $config verify $request $context [dict get $fields csrf]]} {fail 403 "Invalid CSRF token. Reload the form."}
        validate_form $request $fields [dict get $config -operations $view]
        throttle $store [list post [peer $context]] [property $store post_limit]
        if {[dict exists $fields email]} {throttle $store [list $view [email [dict get $fields email]]] [property $store account_limit]}
        if {[dict get $row uid] ne {}} {throttle $store [list $view [dict get $row uid]] [property $store account_limit]}
        # Attempt counts commit independently, including unsuccessful checks.
        if {$challenge || ($view eq "two-factor/setup" && [dict get $fields operation] eq "confirm")} {
            throttle $store [list challenge [dict get $row id]] [property $store challenge_limit]
        }
        db_transaction [dict get $store -connection] {
            set fresh [session $store $token]
            if {$fresh eq {}} {fail 401 "Session expired. Reload the form."}
            set result [{*}$handler $config $fresh $fields]
        }
        if {[dict get $result token] ne {}} {set token [dict get $result token]}
        deliver_after_commit $config [dict get $result delivery]
        set extra [dict create message [dict get $result message] debug_code [dict get $result debug_code]]
        return [set_cookie $config [render $config [dict get $result view] $token $extra] $token]
    } trap {WEB USER} {message opts} {
        response [lindex [dict get $opts -errorcode] 2] "$message\n" {text/plain; charset=utf-8}
    }
}
proc ::web::user::peer {context} {
    # Trusted server context only; do not trust X-Forwarded-For from the request.
    if {[dict exists $context addr]} {return [dict get $context addr]}
    return unknown
}

proc ::web::user::account {config request context params} {
    handle $config account {} 0 $request $context
}

proc ::web::user::register {config request context params} {
    handle $config register ::web::user::action_register 0 $request $context
}

proc ::web::user::verify {config request context params} {
    handle $config verify ::web::user::action_verify 1 $request $context
}

proc ::web::user::login {config request context params} {
    handle $config login ::web::user::action_login 0 $request $context
}

proc ::web::user::forgot {config request context params} {
    handle $config forgot ::web::user::action_forgot 0 $request $context
}

proc ::web::user::reset {config request context params} {
    handle $config reset ::web::user::action_reset 1 $request $context
}

proc ::web::user::change_password {config request context params} {
    handle $config change-password ::web::user::action_change_password 0 $request $context
}

proc ::web::user::two_factor {config request context params} {
    handle $config two-factor ::web::user::action_two_factor 1 $request $context
}

proc ::web::user::two_factor_setup {config request context params} {
    handle $config two-factor/setup ::web::user::action_two_factor_setup 0 $request $context
}

proc ::web::user::two_factor_disable {config request context params} {
    handle $config two-factor/disable ::web::user::action_two_factor_disable 0 $request $context
}

proc ::web::user::logout {config request context params} {
    handle $config logout ::web::user::action_logout 0 $request $context
}

proc ::web::user::profile {config request context params} {
    handle $config profile ::web::user::action_profile 0 $request $context
}
