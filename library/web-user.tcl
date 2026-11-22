package require web-user::config 1.0
package require web-user::routes 1.0.1
package require web-user::request 1.0
# 
# Copyright Jerily LTD. All Rights Reserved.
# SPDX-FileCopyrightText: 2026 Neofytos Dimitriou (neo@jerily.cy)
# SPDX-License-Identifier: MIT.
# 

# Load the account package and its storage dependencies.
package require Tcl 9.1
namespace eval ::web::user {
    variable root [file dirname [file dirname [info script]]]
    foreach {name version} {tpersist 0.1.8 tpathexp 1.1.0 tjson 1.0.27 tink 20240704.0.2 tsession 2.0.1 twebserver 1.47.56 ksuid 1.0.5 topenapi 0.2.0} {
        package require $name $version
    }
    namespace import ::tpersist::db_*
    foreach module {storage settings permissions validation crypto profiles sessions captcha email registrations maintenance migrate-user-ids service email-login http admin widgets oauth mount} {
        source [file join $root library $module.tcl]
    }
    unset name version module
}
package provide web-user 0.7.4
