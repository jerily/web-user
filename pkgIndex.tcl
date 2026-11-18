# 
# Copyright Jerily LTD. All Rights Reserved.
# SPDX-FileCopyrightText: 2026 Neofytos Dimitriou (neo@jerily.cy)
# SPDX-License-Identifier: MIT.
# 

# Register the package and load its dependencies.
package ifneeded web-user 0.7.3 [list source [file join $dir library web-user.tcl]]

package ifneeded web-user::routes 1.0 [list source [file join $dir library routes.tcl]]

package ifneeded web-user::config 1.0 [list source [file join $dir library config.tcl]]
package ifneeded web-user::request 1.0 [list source [file join $dir library request.tcl]]
