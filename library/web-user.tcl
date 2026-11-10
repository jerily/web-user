package require Tcl 8.6 9
foreach {name version} {tpersist 0.1.0 tpathexp 1.1.0 jinja2 0.1.0 tjson 1.0.26 tink 20240704.0.2 bcrypt 2.0.1 tsession 1.0.4 twebserver 1.47.55 tmfa 1.1.2 tqrcodegen 1.1 ksuid 1.0} {
    package require $name $version
}
namespace eval ::web::user {
    variable root [file dirname [file dirname [info script]]]
    namespace import ::tpersist::db_*
}
foreach module {storage crypto sessions service http mount} {
    source [file join $::web::user::root library $module.tcl]
}
package provide web-user 0.1.1
