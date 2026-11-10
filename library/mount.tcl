proc ::web::user::mount {router args} {
    variable root
    set c [options {-store {} -prefix /user -config {} -deliver {}} {*}$args]
    set settings [options {master_template {} templates {} title Account issuer Community origin {}} {*}[dict get $c -config]]
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
    ::tmfa::keyuri MZXW6 totp test -issuer [dict get $settings issuer]
    set name web_user_[string range [tag $store $prefix cookie] end-23 end]
    if {[dict get $store -env] eq "PROD"} {set name __Host-$name}
    dict set c -cookie $name
    set templates {}
    foreach filename {page.html.jinja form.html.jinja} {dict set templates $filename [read_text [file join $root assets $filename]]}
    set templates [dict merge $templates [dict get $settings templates]]
    if {[dict get $settings master_template] ne {}} {dict set templates page.html.jinja [dict get $settings master_template]}
    dict for {name text} $templates {::jinja2::validate $text -templates $templates -path $name}
    dict set c -templates $templates
    set routes [list $prefix account $prefix/ account]
    foreach path {register verify login forgot reset two-factor two-factor/setup two-factor/disable logout} {lappend routes $prefix/$path $path}
    foreach {path action} $routes {
        if {[dict get [$router match GET $path] statusCode] != 404} {error "route already mounted: $path"}
    }
    foreach {path action} $routes {
        set methods [expr {$action eq "account" ? "GET" : ($action eq "logout" ? "POST" : "GET POST")}]
        $router add $methods $path [list ::web::user::dispatch $c $action] -strict true
    }
    return $c
}
