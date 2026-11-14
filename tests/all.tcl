#
# Copyright Jerily LTD. All Rights Reserved.
# SPDX-FileCopyrightText: 2026 Neofytos Dimitriou (neo@jerily.cy)
# SPDX-License-Identifier: MIT.
#

package require tcltest 2
set packageRoot [file dirname [file dirname [file normalize [info script]]]]
lappend auto_path $packageRoot
# Exercise this checkout even when the same version is already installed.
source [file join $packageRoot library web-user.tcl]
::tcltest::configure -singleproc true -testdir [file dirname [info script]] {*}$argv
exit [::tcltest::runAllTests]
