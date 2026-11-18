# SPDX-License-Identifier: MIT
# Optional request lifetime for read-only HTTP identity/session snapshots.
# State stays inside the package; request dictionaries cannot supply cached identities.
namespace eval ::web::user {variable request_scopes {}}

# Hosts wrap the entire dispatch, including their response/navigation work.
# Each coroutine has an independent scope; nested requests restore their parent.
proc ::web::user::with_request {method script} {
    variable request_scopes
    set key [info coroutine]
    set previous {}
    set existed [dict exists $request_scopes $key]
    if {$existed} {set previous [dict get $request_scopes $key]}
    dict set request_scopes $key [dict create enabled [expr {$method in {GET HEAD}}] values {}]
    try {
        uplevel 1 $script
    } finally {
        if {$existed} {dict set request_scopes $key $previous} else {dict unset request_scopes $key}
    }
}

proc ::web::user::request_get {key valueVar} {
    variable request_scopes
    set scope [info coroutine]
    if {![dict exists $request_scopes $scope] || ![dict get $request_scopes $scope enabled] ||
        ![dict exists $request_scopes $scope values $key]} {return false}
    upvar 1 $valueVar value
    set value [dict get $request_scopes $scope values $key]
    return true
}

proc ::web::user::request_put {key value} {
    variable request_scopes
    set scope [info coroutine]
    if {[dict exists $request_scopes $scope] && [dict get $request_scopes $scope enabled]} {
        dict set request_scopes $scope values $key $value
    }
    return $value
}

# Call after an out-of-band account/session change inside a host's read scope.
# Ordinary web-user mutation APIs invalidate automatically.
proc ::web::user::request_invalidate {} {
    variable request_scopes
    set scope [info coroutine]
    if {[dict exists $request_scopes $scope]} {dict set request_scopes $scope values {}}
}

# Mutation flows use fresh reads for the rest of this request, including any
# error response after a rollback. This also covers GET OAuth callbacks.
proc ::web::user::request_mutating {} {
    variable request_scopes
    set scope [info coroutine]
    if {[dict exists $request_scopes $scope]} {
        dict set request_scopes $scope enabled false
        dict set request_scopes $scope values {}
    }
}

# Standalone mounts establish a scope; hosts may already own a wider one.
proc ::web::user::request_dispatch {handler request context params} {
    variable request_scopes
    if {[dict exists $request_scopes [info coroutine]]} {
        return [{*}$handler $request $context $params]
    }
    with_request [dict get $request method] [list {*}$handler $request $context $params]
}

package provide web-user::request 1.0
