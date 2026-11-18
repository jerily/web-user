# SPDX-License-Identifier: MIT
# Route declarations only. This package never loads storage or handlers.
namespace eval ::web::user {
    variable template_directory [file normalize [file join [file dirname [info script]] .. assets]]
}

# Config is opaque here: hosts may bind a placeholder and resolve it on dispatch.
proc ::web::user::route_specs {prefix config {settings {}} {policy {}}} {
    set prefix [string trimright $prefix /]
    if {![regexp {^(/[A-Za-z0-9_-]+)+$} $prefix]} {error "mount prefix must be a non-root local path"}
    set settings [dict merge {google_enabled false email_login_enabled false} $settings]
    set policy [dict merge {collect_names false collect_display_name false collect_username false} $policy]
    foreach key {google_enabled email_login_enabled} {
        if {![string is boolean -strict [dict get $settings $key]]} {error "$key must be a boolean"}
    }
    set routes {}
    if {[dict get $settings google_enabled]} {
        lappend routes [list GET $prefix/google/link [list ::web::user::google_link $config]]
        lappend routes [list POST $prefix/google/start [list ::web::user::google_start $config]]
        lappend routes [list GET $prefix/google/callback [list ::web::user::google_callback $config]]
        lappend routes [list POST $prefix/google/unlink [list ::web::user::google_unlink $config]]
    }
    if {[dict get $settings email_login_enabled]} {
        lappend routes [list {GET POST} $prefix/email-login [list ::web::user::email_login $config]]
        lappend routes [list {GET POST} $prefix/email-login/verify [list ::web::user::email_login_verify $config]]
    }
    lappend routes [list GET $prefix [list ::web::user::account $config]]
    lappend routes [list GET $prefix/ [list ::web::user::account $config]]
    lappend routes [list GET $prefix/admin/users [list ::web::user::admin_users $config]]
    lappend routes [list GET $prefix/_assets/admin.css ::web::user::admin_stylesheet]
    lappend routes [list {GET POST} $prefix/register [list ::web::user::register $config]]
    lappend routes [list {GET POST} $prefix/verify [list ::web::user::verify $config]]
    lappend routes [list POST $prefix/resend-verification [list ::web::user::resend_verification $config]]
    lappend routes [list {GET POST} $prefix/login [list ::web::user::login $config]]
    lappend routes [list {GET POST} $prefix/forgot [list ::web::user::forgot $config]]
    lappend routes [list {GET POST} $prefix/reset [list ::web::user::reset $config]]
    lappend routes [list {GET POST} $prefix/change-password [list ::web::user::change_password $config]]
    lappend routes [list {GET POST} $prefix/close-account [list ::web::user::close_account $config]]
    lappend routes [list {GET POST} $prefix/two-factor [list ::web::user::two_factor $config]]
    lappend routes [list {GET POST} $prefix/two-factor/setup [list ::web::user::two_factor_setup $config]]
    lappend routes [list {GET POST} $prefix/two-factor/disable [list ::web::user::two_factor_disable $config]]
    if {[dict get $policy collect_names] || [dict get $policy collect_display_name] || [dict get $policy collect_username]} {
        lappend routes [list {GET POST} $prefix/profile [list ::web::user::profile $config]]
    }
    lappend routes [list POST $prefix/logout [list ::web::user::logout $config]]
    return $routes
}
package provide web-user::routes 1.0
