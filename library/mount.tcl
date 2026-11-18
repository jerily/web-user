#
# Copyright Jerily LTD. All Rights Reserved.
# SPDX-FileCopyrightText: 2026 Neofytos Dimitriou (neo@jerily.cy)
# SPDX-License-Identifier: MIT.
#

# Validate configuration and mount the account routes and templates.
proc ::web::user::mount {router args} {
    set config [prepare_mount {*}$args]
    try {mount_configured $router $config} on error {message opts} {
        release $config
        return -options $opts $message
    }
}
proc ::web::user::prepare_configured {config} {
    variable root
    set settings [options {prefix /user deliver {} email_enabled false email_from {} email_region {} email_queue_enabled false email_queue_url {} email_queue_callback {} email_login_enabled false master_template {} templates {} template_renderer {} title Account issuer {} origin {} properties {} assets_url {} google_enabled false google_client_id {} google_redirect_uri {} validate_templates true} {*}[dict get $config -config]]
    if {![string is boolean -strict [dict get $settings email_login_enabled]]} {error "email_login_enabled must be a boolean"}
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
    if {[dict get $settings assets_url] eq {}} {dict set settings assets_url $prefix/_assets}
    dict set settings assets_url [string trimright [dict get $settings assets_url] /]
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
    if {[dict get $settings template_renderer] eq {}} {
        dict set config -templates [prepare_templates $settings]
    }
    dict set config -operations [request_operations $store]
    validate_email_config $config
    return [google_configure $config]
}

proc ::web::user::prepare_mount {args} {
    set config [mount_store [options {-store {} -connection {} -policy {} -config {} -secret_config {}} {*}$args]]
    try {prepare_configured $config} on error {message opts} {
        release $config
        return -options $opts $message
    }
}

proc ::web::user::mount_configured {router config} {
    set prefix [dict get $config -prefix]
    set settings [dict get $config -config]
    # Check collisions before installing any route.
    foreach path [list $prefix $prefix/ $prefix/register $prefix/verify $prefix/resend-verification $prefix/login \
        $prefix/forgot $prefix/reset $prefix/change-password $prefix/close-account $prefix/two-factor $prefix/two-factor/setup \
        $prefix/two-factor/disable $prefix/logout $prefix/profile $prefix/admin/users $prefix/_assets/admin.css $prefix/google/link $prefix/google/start $prefix/google/callback $prefix/google/unlink $prefix/email-login $prefix/email-login/verify] {
        if {[dict get [$router match GET $path] statusCode] != 404} {error "route already mounted: $path"}
    }
    foreach route [::web::user::route_specs $prefix $config $settings [dict get $config -store -config]] {
        lassign $route method path handler
        $router add $method $path [list ::web::user::request_dispatch $handler] -strict true
    }
    return $config
}

# Prepare the exact host/package composition without opening storage or mounting
# routes. Production hosts may skip validation after checking their artifact.
proc ::web::user::prepare_templates {{settings {}}} {
    package require jinja2 0.2.0
    variable root
    set settings [dict merge {master_template {} templates {} template_renderer {} validate_templates true} $settings]
    if {![string is boolean -strict [dict get $settings validate_templates]]} {error "validate_templates must be a boolean"}
    set templates {}
    foreach filename {page.html.jinja form.html.jinja profile.html.jinja admin-users.html.jinja} {dict set templates $filename [read_text [file join $root assets $filename]]}
    if {[dict get $settings validate_templates]} {
        dict for {name text} $templates {::jinja2::validate $text -templates $templates -path $name}
    }
    set templates [dict merge $templates [dict get $settings templates]]
    if {[dict get $settings master_template] ne {}} {dict set templates page.html.jinja [dict get $settings master_template]}
    if {[dict get $settings validate_templates]} {
        dict for {name text} $templates {::jinja2::validate $text -templates $templates -path $name}
    }
    return $templates
}

# Hosts may render by name without supplying template strings in mount options.
proc ::web::user::render_template {config name json} {
    set renderer [dict get $config -config template_renderer]
    if {$renderer ne {}} {return [{*}$renderer $name $json]}
    package require jinja2 0.2.0
    set templates [dict get $config -templates]
    ::jinja2::render [dict get $templates $name] $json -templates $templates -path $name
}
