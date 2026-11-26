package require web-user::manifest
package require web-user::config
package require web-user::request
# 
# Copyright Jerily LTD. All Rights Reserved.
# SPDX-FileCopyrightText: 2026 Neofytos Dimitriou (neo@jerily.cy)
# SPDX-License-Identifier: MIT.
# 

# Load the account package and its storage dependencies.
package require Tcl
namespace eval ::web::user {
    variable root [file dirname [file dirname [info script]]]
    foreach name {tpersist tpathexp tjson tink tsession twebserver ksuid topenapi} {
        package require $name
    }
    namespace import ::tpersist::db_*
    foreach module {storage settings permissions validation crypto profiles sessions captcha email registrations maintenance migrate-user-ids service email-login http admin widgets oauth mount} {
        source [file join $root library $module.tcl]
    }
    unset name module
}
package provide web-user 1.1.1
