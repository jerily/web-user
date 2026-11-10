# Names are collected only when enabled by the host. Keep Unicode and punctuation.
proc ::web::user::name_fields {store fields} {
    if {![property $store collect_names]} {return {}}
    set names {}
    foreach key {first_name last_name} {
        if {![dict exists $fields $key]} {fail 400 "Enter your first and last name."}
        set value [string trim [dict get $fields $key]]
        if {$value eq {} || [string length $value] > 100 || [regexp {[\x00-\x1f\x7f]} $value]} {
            fail 400 "Names must contain 1 to 100 characters and no control characters."
        }
        dict set names $key $value
    }
    return $names
}

# Called in the user's transaction after registration or a successful user CAS.
proc ::web::user::save_profile {store uid names} {
    set encrypted {}
    dict for {key value} $names {dict set encrypted $key [seal $store $value [list profile $uid $key]]}
    if {[one $store web_user_profiles [dict create id $uid]] eq {}} {
        insert $store web_user_profiles [dict merge [dict create id $uid] $encrypted]
    } else {
        update $store web_user_profiles [dict create id $uid] $encrypted
    }
}

# Full names are available only through the authenticated account API.
proc ::web::user::profile_names {store uid} {
    set names [dict create first_name {} last_name {}]
    set row [one $store web_user_profiles [dict create id $uid]]
    if {$row ne {}} {
        foreach key {first_name last_name} {
            dict set names $key [unseal $store [dict get $row $key] [list profile $uid $key]]
        }
    }
    return $names
}

# Public consumers receive the first name as display_name, never email or surname.
proc ::web::user::public_profile {store uid} {
    set displayName Member
    if {$uid ne {}} {
        set user [user_by_id $store $uid]
        if {$user ne {} && [dict get $user verified]} {
            set row [one $store web_user_profiles [dict create id $uid]]
            if {$row ne {}} {
                set firstName [unseal $store [dict get $row first_name] [list profile $uid first_name]]
                if {$firstName ne {}} {set displayName $firstName}
            }
        }
    }
    dict create display_name $displayName
}
