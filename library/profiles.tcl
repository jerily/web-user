#
# Copyright Jerily LTD. All Rights Reserved.
# SPDX-FileCopyrightText: 2026 Neofytos Dimitriou (neo@jerily.cy)
# SPDX-License-Identifier: MIT.
#

# Names are collected only when enabled by the host. Keep Unicode and punctuation.
proc ::web::user::name_fields {store fields} {
    set names {}
    set required {}
    if {[property $store collect_names]} {lappend required first_name last_name}
    if {[property $store collect_display_name]} {lappend required display_name}
    foreach key $required {
        if {$key eq "display_name" && (![dict exists $fields $key] || [string trim [dict get $fields $key]] eq {})} {dict set names $key {}; continue}
        if {![dict exists $fields $key]} {fail 400 "Enter the requested profile names."}
        set maximum [expr {$key eq "display_name" ? 80 : 100}]
        set value [string trim [dict get $fields $key]]
        if {$value eq {} || [string length $value] > $maximum || [regexp {[\x00-\x1f\x7f]} $value]} {
            fail 400 "Profile names must contain 1 to $maximum characters and no control characters."
        }
        dict set names $key $value
    }
    return $names
}

# Called in the user's transaction after registration or a successful user CAS.
proc ::web::user::save_profile {store uid names} {
    if {$names eq {}} {return}
    set encrypted {}
    dict for {key value} $names {
        dict set encrypted $key [expr {$value eq {} ? {} : [seal $store $value [list profile $uid $key]]}]
    }
    if {[one $store web_user_profiles [dict create id $uid]] eq {}} {
        insert $store web_user_profiles [dict merge [dict create id $uid first_name {} last_name {} display_name {}] $encrypted]
    } else {
        update $store web_user_profiles [dict create id $uid] $encrypted
    }
}

# Full names are available only through the authenticated account API.
proc ::web::user::profile_names {store uid} {
    if {[request_get [list profile_names $store $uid] names]} {return $names}
    set row [one $store web_user_profiles [dict create id $uid]]
    profile_decode $store $uid $row
}

proc ::web::user::profile_decode {store uid row} {
    set names [dict create first_name {} last_name {} display_name {}]
    if {$row ne {}} {
        foreach key {first_name last_name display_name} {
            if {[dict get $row $key] ne {}} {dict set names $key [unseal $store [dict get $row $key] [list profile $uid $key]]}
        }
    }
    request_put [list profile_names $store $uid] $names
}

# Public consumers receive a display name and handle, never email or surname.
proc ::web::user::public_profile {store uid} {
    set displayName Member
    set username {}
    if {$uid ne {}} {
        set user [user_by_id $store $uid]
        if {$user ne {} && [dict get $user active]} {
            set names [profile_names $store $uid]
            set displayName [profile_display_name $names]
            set username [dict get $user username]
        }
    }
    dict create display_name $displayName username $username
}

# Prefer an explicit public name, then a first name, without exposing surnames.
proc ::web::user::profile_display_name {names} {
    foreach key {display_name first_name} {
        if {[dict get $names $key] ne {}} {return [dict get $names $key]}
    }
    return Member
}

# Normalize an optional public handle; email remains the sign-in identifier.
proc ::web::user::username_field {store fields} {
    if {![property $store collect_username]} {return {}}
    if {![dict exists $fields username]} {fail 400 "Enter a username."}
    set value [string tolower [string trim [dict get $fields username]]]
    if {![regexp {^[a-z][a-z0-9_]{2,31}$} $value]} {
        fail 400 "Username must start with a letter and contain 3–32 letters, digits, or underscores."
    }
    return $value
}

# Test a normalized handle before writing; the unique constraint still wins races.
proc ::web::user::check_username {store username {uid {}}} {
    if {$username eq {}} {return}
    set owner [one $store web_user_users [dict create username $username]]
    if {$owner ne {} && [dict get $owner id] ne $uid} {
        return -code error -errorcode {WEB USER 409 USERNAME} "That username is already in use. Choose another username."
    }
}
