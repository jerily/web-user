package require Tcl 9.1
foreach {name version} {tpersist 0.1.1 tpathexp 1.1.0 jinja2 0.1.1 tjson 1.0.27 tink 20240704.0.2 bcrypt 2.0.1 tsession 1.0.4 twebserver 1.47.56 tmfa 1.1.2 tqrcodegen 1.1.1 ksuid 1.0.5 topenapi 0.2.0} {
    package require $name $version
}
namespace eval ::web::user {
    variable root [file dirname [file dirname [info script]]]
    namespace import ::tpersist::db_*
}
foreach module {storage settings validation crypto sessions service http mount} {
    source [file join $::web::user::root library $module.tcl]
}
package provide web-user 0.1.4
