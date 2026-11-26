#
# Copyright Jerily LTD. All Rights Reserved.
# SPDX-FileCopyrightText: 2026 Neofytos Dimitriou (neo@jerily.cy)
# SPDX-License-Identifier: MIT.
#

# Keep post-login destinations on this site, including their query and fragment.
proc ::web::user::safe_return_to {value} {
    if {[string length $value] > 4096 || [regexp {[\x00-\x20\x7f\\]} $value]} {return {}}
    set path [lindex [split $value ?#] 0]
    # Decode the path for validation as well: encoded separators cannot hide an authority.
    if {[catch {decode $path} path] || [regexp {[%\x00-\x20\x7f\\]} $path] ||
        ![string match /* $path] || [string match //* $path]} {return {}}
    return $value
}

# Preserve the original GET destination without carrying submitted form data.
proc ::web::user::request_target {request} {
    set target [dict get $request path]
    if {[dict exists $request queryString] && [dict get $request queryString] ne {}} {
        append target ?[dict get $request queryString]
    }
    safe_return_to $target
}

# Read one optional return destination; invalid destinations are ignored.
proc ::web::user::requested_return_to {request} {
    if {![dict exists $request queryString]} {return {}}
    set value {}
    set seen 0
    foreach pair [split [dict get $request queryString] &] {
        set at [string first = $pair]
        if {$at < 1 || [decode [string range $pair 0 [expr {$at - 1}]]] ne "return_to"} {continue}
        if {$seen} {return {}}
        set seen 1
        set value [decode [string range $pair [expr {$at + 1}] end]]
    }
    safe_return_to $value
}

# Share the destination between login, registration, verification and MFA forms.
proc ::web::user::return_query {target} {
    set target [safe_return_to $target]
    if {$target eq {}} {return {}}
    return ?return_to=[uri_component $target]
}

proc ::web::user::redirect {location} {
    set result [response 302 {}]
    dict set result headers Location $location
    return $result
}

# Hosts can use this for other pages that require authentication too.
proc ::web::user::sign_in_redirect {config request} {
    redirect [dict get $config -prefix]/login[return_query [request_target $request]]
}

proc ::web::user::uri_component {text} {
    package require twebserver 1.47.60
    ::twebserver::encode_uri_component $text
}
