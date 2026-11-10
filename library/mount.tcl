proc ::web::user::mount {router args} {
    variable root
    set config [options {-store {} -config {}} {*}$args]
    set settings [options {prefix /user deliver {} master_template {} templates {} title Account issuer {} origin {} properties {}} {*}[dict get $config -config]]
    foreach key {prefix deliver} {
        dict set config -$key [dict get $settings $key]
    }
    set store [dict get $config -store]
    if {$store eq {}} {error "-store is required"}
    set origin [dict get $settings origin]
    if {![regexp {^https?://[A-Za-z0-9.:-]+$} $origin] || ([dict get $store -env] eq "PROD" && ![string match https://* $origin])} {
        error "origin must be the site's exact origin (HTTPS in PROD)"
    }
    set prefix [string trimright [dict get $config -prefix] /]
    if {![regexp {^(/[A-Za-z0-9_-]+)+$} $prefix]} {error "mount prefix must be a non-root local path"}
    dict set config -prefix $prefix
    dict set config -config $settings
    # Validate the label directly. Provisioning happens only with a user's
    # generated secret and account address during enrollment.
    if {[regexp {[:\x00-\x1f\x7f]} [dict get $settings issuer]]} {
        error "issuer cannot contain colons or control characters"
    }
    set name web_user_[string range [tag $store $prefix cookie] end-23 end]
    if {[dict get $store -env] eq "PROD"} {set name __Host-$name}
    dict set config -cookie $name
    dict set config -session-cookie [::tsession::cookie::create -name $name -mac [dict get $store -mac] \
        -secure [expr {[dict get $store -env] eq "PROD"}]]
    set templates {}
    foreach filename {page.html.jinja form.html.jinja profile.html.jinja} {dict set templates $filename [read_text [file join $root assets $filename]]}
    set templates [dict merge $templates [dict get $settings templates]]
    if {[dict get $settings master_template] ne {}} {dict set templates page.html.jinja [dict get $settings master_template]}
    dict for {name text} $templates {::jinja2::validate $text -templates $templates -path $name}
    dict set config -templates $templates
    dict set config -operations [request_operations $store]
    # Check collisions before installing any route.
    foreach path [list $prefix $prefix/ $prefix/register $prefix/verify $prefix/login \
        $prefix/forgot $prefix/reset $prefix/two-factor $prefix/two-factor/setup \
        $prefix/two-factor/disable $prefix/logout $prefix/profile] {
        if {[dict get [$router match GET $path] statusCode] != 404} {error "route already mounted: $path"}
    }
    $router add GET $prefix [list ::web::user::account $config] -strict true
    $router add GET $prefix/ [list ::web::user::account $config] -strict true
    $router add {GET POST} $prefix/register [list ::web::user::register $config] -strict true
    $router add {GET POST} $prefix/verify [list ::web::user::verify $config] -strict true
    $router add {GET POST} $prefix/login [list ::web::user::login $config] -strict true
    $router add {GET POST} $prefix/forgot [list ::web::user::forgot $config] -strict true
    $router add {GET POST} $prefix/reset [list ::web::user::reset $config] -strict true
    $router add {GET POST} $prefix/two-factor [list ::web::user::two_factor $config] -strict true
    $router add {GET POST} $prefix/two-factor/setup [list ::web::user::two_factor_setup $config] -strict true
    $router add {GET POST} $prefix/two-factor/disable [list ::web::user::two_factor_disable $config] -strict true
    if {[property $store collect_names]} {
        $router add {GET POST} $prefix/profile [list ::web::user::profile $config] -strict true
    }
    $router add POST $prefix/logout [list ::web::user::logout $config] -strict true
    return $config
}
