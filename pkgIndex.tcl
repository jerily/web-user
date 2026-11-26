# 
# Copyright Jerily LTD. All Rights Reserved.
# SPDX-FileCopyrightText: 2026 Neofytos Dimitriou (neo@jerily.cy)
# SPDX-License-Identifier: MIT.
# 

# Register the package and load its dependencies.
package ifneeded web-user 1.1.1 [list source [file join $dir library web-user.tcl]]


package ifneeded web-user::config 1.0 [list source [file join $dir library config.tcl]]
package ifneeded web-user::request 1.0 [list source [file join $dir library request.tcl]]

# Locate the manifest without loading application services.
package ifneeded web-user::manifest 1.1.1 [list apply {{dir} {
    package require web-core
    ::web::core::register web-user $dir
    package provide web-user::manifest 1.1.1
}} $dir]
