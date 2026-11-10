proc ::web::user::mount {router args} {
    variable root
    set c [options {-store {} -prefix {} -config {} -deliver {}} {*}$args]
    set settings [options {prefix /user deliver {} master_template {} templates {} title Account issuer {} origin {} properties {}} {*}[dict get $c -config]]
    foreach key {prefix deliver} {
        if {[dict get $c -$key] ne {}} {dict set settings $key [dict get $c -$key]}
        dict set c -$key [dict get $settings $key]
    }
    set store [dict get $c -store]
    if {$store eq {}} {error "-store is required"}
    set origin [dict get $settings origin]
    if {![regexp {^https?://[A-Za-z0-9.:-]+$} $origin] || ([dict get $store -env] eq "PROD" && ![string match https://* $origin])} {
        error "origin must be the site's exact origin (HTTPS in PROD)"
    }
    set prefix [string trimright [dict get $c -prefix] /]
    if {![regexp {^(/[A-Za-z0-9_-]+)+$} $prefix]} {error "mount prefix must be a non-root local path"}
    dict set c -prefix $prefix
    dict set c -config $settings
    # Validate the label directly. Provisioning happens only with a user's
    # generated secret and account address during enrollment.
    if {[regexp {[:\x00-\x1f\x7f]} [dict get $settings issuer]]} {
        error "issuer cannot contain colons or control characters"
    }
    set name web_user_[string range [tag $store $prefix cookie] end-23 end]
    if {[dict get $store -env] eq "PROD"} {set name __Host-$name}
    dict set c -cookie $name
    dict set c -session-cookie [::tsession::cookie::create -name $name -mac [dict get $store -mac] \
        -secure [expr {[dict get $store -env] eq "PROD"}]]
    set templates {}
    foreach filename {page.html.jinja form.html.jinja} {dict set templates $filename [read_text [file join $root assets $filename]]}
    set templates [dict merge $templates [dict get $settings templates]]
    if {[dict get $settings master_template] ne {}} {dict set templates page.html.jinja [dict get $settings master_template]}
    dict for {name text} $templates {::jinja2::validate $text -templates $templates -path $name}
    dict set c -templates $templates
    # Check collisions before installing any route.
    foreach path [list $prefix $prefix/ $prefix/register $prefix/verify $prefix/login \
        $prefix/forgot $prefix/reset $prefix/two-factor $prefix/two-factor/setup \
        $prefix/two-factor/disable $prefix/logout] {
        if {[dict get [$router match GET $path] statusCode] != 404} {error "route already mounted: $path"}
    }
    $router add GET $prefix [list ::web::user::account $c] -strict true
    $router add GET $prefix/ [list ::web::user::account $c] -strict true
    $router add {GET POST} $prefix/register [list ::web::user::register $c] -strict true
    $router add {GET POST} $prefix/verify [list ::web::user::verify $c] -strict true
    $router add {GET POST} $prefix/login [list ::web::user::login $c] -strict true
    $router add {GET POST} $prefix/forgot [list ::web::user::forgot $c] -strict true
    $router add {GET POST} $prefix/reset [list ::web::user::reset $c] -strict true
    $router add {GET POST} $prefix/two-factor [list ::web::user::two_factor $c] -strict true
    $router add {GET POST} $prefix/two-factor/setup [list ::web::user::two_factor_setup $c] -strict true
    $router add {GET POST} $prefix/two-factor/disable [list ::web::user::two_factor_disable $c] -strict true
    $router add POST $prefix/logout [list ::web::user::logout $c] -strict true
    return $c
}
