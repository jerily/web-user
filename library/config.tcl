# SPDX-License-Identifier: MIT
# Public configuration and navigation helpers, without account services.
namespace eval ::web::user {}

proc ::web::user::access_config {groups permissions} {
    set result [dict create groups {} permissions {}]
    dict for {group addresses} $groups {
        if {![regexp {^[a-z][a-z0-9_-]{0,63}$} $group]} {error "invalid group name: $group"}
        set members {}
        foreach address [split $addresses ,] {
            if {[string trim $address] eq {}} {continue}
            lappend members [email $address]
        }
        dict set result groups $group [lsort -unique $members]
    }
    dict for {group names} $permissions {
        if {![dict exists $result groups $group]} {error "permissions refer to an undefined group: $group"}
        set grants {}
        foreach name [split $names ,] {
            set name [string trim $name]
            if {$name eq {}} {continue}
            if {![regexp {^[a-z][a-z0-9_.:-]{0,127}$} $name]} {error "invalid permission: $name"}
            lappend grants $name
        }
        dict set result permissions $group [lsort -unique $grants]
    }
    return $result
}
# Normalize and validate an email address.
proc ::web::user::email {value} {
    set value [string tolower [string trim $value]]
    if {[string length $value] > 254 || ![regexp {^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$} $value]} {
        fail 400 "Enter a valid email address."
    }
    return $value
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

# Return a structured account HTTP error.
proc ::web::user::fail {status message} {return -code error -errorcode [list WEB USER $status] $message}

source [file join [file dirname [info script]] navigation.tcl]
package provide web-user::config 1.0
