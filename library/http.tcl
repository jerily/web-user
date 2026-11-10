proc ::web::user::fail {status message} {return -code error -errorcode [list WEB USER $status] $message}
proc ::web::user::response {status body {type {text/html; charset=utf-8}}} {
    dict create statusCode $status body $body headers [dict create content-type $type \
        cache-control no-store x-content-type-options nosniff referrer-policy no-referrer \
        content-security-policy {default-src 'self'; style-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'}]
}
proc ::web::user::header {request name} {
    if {[dict exists $request headers]} {
        dict for {key value} [dict get $request headers] {if {[string equal -nocase $key $name]} {return $value}}
    }
    return {}
}
proc ::web::user::cookie_token {config request} {
    set result {}
    foreach pair [split [header $request cookie] {;}] {
        set parts [split [string trim $pair] =]
        if {[lindex $parts 0] eq [dict get $config -cookie]} {
            if {$result ne {} || [llength $parts] != 2} {return {}}
            set result [lindex $parts 1]
        }
    }
    return $result
}
proc ::web::user::set_cookie {config response token} {
    set cookie "[dict get $config -cookie]=$token; Path=/; HttpOnly; SameSite=Lax"
    if {[dict get $config -store -env] eq "PROD"} {append cookie "; Secure"}
    dict set response headers set-cookie $cookie
    return $response
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
    expr {[::tink::constant_time_equal [csrf_token $config $token] $submitted] &&
        ([header $request origin] eq {} || [header $request origin] eq [dict get $config -config origin])}
}
proc ::web::user::decode {value} {
    set value [string map {+ { }} $value]
    set bytes {}
    for {set i 0} {$i < [string length $value]} {incr i} {
        set c [string index $value $i]
        if {$c eq "%"} {
            set hex [string range $value [expr {$i+1}] [expr {$i+2}]]
            if {![regexp {^[a-fA-F0-9]{2}$} $hex]} {fail 400 "Invalid percent encoding."}
            append bytes [binary format H2 $hex]
            incr i 2
        } else {append bytes [encoding convertto utf-8 $c]}
    }
    if {[catch {encoding convertfrom utf-8 $bytes} text] || [encoding convertto utf-8 $text] ne $bytes || [string first \x00 $text] >= 0} {
        fail 400 "Invalid UTF-8 form."
    }
    return $text
}
proc ::web::user::form {request} {
    if {[string tolower [string trim [lindex [split [header $request content-type] {;}] 0]]] ne "application/x-www-form-urlencoded"} {fail 415 "Use URL-encoded form data."}
    if {![dict exists $request body]} {fail 400 "Missing form body."}
    set body [dict get $request body]
    if {[string length $body] > 32768} {fail 413 "Form too large."}
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
        csrf [csrf_token $config $token] message {} debug_code {} email {} qr {} secret {}] $extra]
    set enabled 0
    if {$user ne {}} {
        set public [public_user $store $user]
        dict set fields email [dict get $public email]
        set enabled [dict get $public mfa_enabled]
    }
    if {$view in {account two-factor/setup two-factor/disable}} {require_user $store $row}
    if {$view eq "two-factor/setup" && [dict get $row pending_secret] ne {}} {
        set secret [unseal $store [dict get $row pending_secret] [list mfa [dict get $user id]]]
        set uri [::tmfa::keyuri $secret totp [dict get $fields email] -issuer [dict get $config -config issuer]]
        dict set fields qr [::tqrcodegen::encode_to_svg $uri]
        dict set fields secret $secret
        if {[dict get $store -env] eq "LOCAL"} {dict set fields debug_code [::tmfa::get_totp $secret 6 30 SHA1]}
    }
    if {$view eq "two-factor" && $row ne {} && [dict get $row kind] eq "two-factor" && [dict get $store -env] eq "LOCAL"} {
        set pending [user_by_id $store [dict get $row uid]]
        if {$pending ne {} && [dict get $pending mfa_secret] ne {}} {
            dict set fields debug_code [::tmfa::get_totp [unseal $store [dict get $pending mfa_secret] [list mfa [dict get $pending id]]] 6 30 SHA1]
        }
    }
    if {$view eq "two-factor/disable" && $user ne {} && $enabled && [dict get $store -env] eq "LOCAL"} {
        dict set fields debug_code [::tmfa::get_totp [unseal $store [dict get $user mfa_secret] [list mfa [dict get $user id]]] 6 30 SHA1]
    }
    if {[dict get $store -env] ne "LOCAL"} {dict set fields debug_code {}}
    set context [text_fields $fields]
    dict set context mfa_enabled [list BOOL $enabled]
    set templates [dict get $config -templates]
    response 200 [::jinja2::render [dict get $templates form.html.jinja] \
        [::tjson::typed_to_json [list M $context]] -templates $templates -path form.html.jinja]
}
proc ::web::user::dispatch {config action request context params} {
    try {
        set store [dict get $config -store]
        set token [cookie_token $config $request]
        set row [session $store $token]
        if {[dict get $request method] ne "POST"} {
            if {$row eq {}} {
                # Avoid unbounded anonymous-session creation from one peer.
                throttle $store [list browse [peer $context]] 120
                set token [new_session $store]
            }
            return [set_cookie $config [render $config $action $token] $token]
        }
        set fields [form $request]
        if {$row eq {} || ![dict exists $fields csrf] || ![csrf $config verify $request $context [dict get $fields csrf]]} {fail 403 "Invalid CSRF token. Reload the form."}
        foreach key [dict get {register {email password} verify code login {email password} forgot email reset {code password} two-factor code two-factor/setup operation two-factor/disable {password code} logout {}} $action] {
            if {![dict exists $fields $key]} {fail 400 "Missing form field: $key"}
        }
        if {$action eq "two-factor/setup"} {
            set key [expr {[dict get $fields operation] eq "begin" ? "password" : "code"}]
            if {![dict exists $fields $key]} {fail 400 "Missing form field: $key"}
        }
        throttle $store [list post [peer $context]] 60
        if {[dict exists $fields email]} {throttle $store [list $action [email [dict get $fields email]]] 10}
        if {[dict get $row uid] ne {}} {throttle $store [list $action [dict get $row uid]] 10}
        # Attempt counts commit independently, including unsuccessful checks.
        if {$action in {verify reset two-factor} || ($action eq "two-factor/setup" && [dict get $fields operation] eq "confirm")} {
            throttle $store [list challenge [dict get $row id]] 5
        }
        db_transaction [dict get $store -connection] {
            set fresh [session $store $token]
            if {$fresh eq {}} {fail 401 "Session expired. Reload the form."}
            set result [transition $config $action $fresh $fields]
        }
        if {[dict get $result token] ne {}} {set token [dict get $result token]}
        if {[dict get $result delivery] ne {}} {deliver $config {*}[dict get $result delivery]}
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
