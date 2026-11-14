#
# Copyright Jerily LTD. All Rights Reserved.
# SPDX-FileCopyrightText: 2026 Neofytos Dimitriou (neo@jerily.cy)
# SPDX-License-Identifier: MIT.
#

# Migrate the legacy mixed user table once, during explicit schema maintenance.
proc ::web::user::migrate_registrations {connection} {
    set name separate-registrations-v1
    set where [db_eq [db_col name] [db_value $name]]
    db_transaction $connection {
        if {![llength [dict get [db_execute $connection [db_where [db_select web_user_migrations] $where]] rows]]} {
            foreach user [dict get [db_execute $connection [db_select web_user_users]] rows] {
                set user [dict merge {username {}} $user]
                set store [dict create -connection $connection -tenant [dict get $user tenant]]
                if {[dict get $user verified]} {
                    update $store web_user_users [dict create id [dict get $user id]] {active 1}
                    continue
                }
                set uid [dict get $user id]
                set pending [dict create id $uid first_name {} last_name {} display_name {} expires 0]
                foreach key {email_key email password username created_at} {dict set pending $key [dict get $user $key]}
                set profile [one $store web_user_profiles [dict create id $uid]]
                if {$profile ne {}} {
                    foreach key {first_name last_name display_name} {dict set pending $key [dict get $profile $key]}
                }
                foreach session [rows $store tsession_sessions [dict create subject $uid]] {
                    set data [dict get $session data]
                    if {[dict exists $data kind] && [dict get $data kind] eq "verify"} {
                        dict set pending expires [expr {max([dict get $pending expires], [dict get $session expires])}]
                    }
                }
                insert $store web_user_registrations $pending
                remove $store web_user_profiles [dict create id $uid]
                remove $store web_user_users [dict create id $uid]
            }
            db_execute $connection [db_values [db_insert web_user_migrations] \
                [dict create name [db_value $name] applied_at [db_value [clock seconds] -type bigint]] -expressions]
        }
    }
}

# Delete a bounded batch after the grace period, preserving renewed rows.
proc ::web::user::prune_table {store table batch} {
    if {![string is integer -strict $batch] || $batch < 1 || $batch > 10000} {error "batch must be 1..10000"}
    set cutoff [expr {[clock seconds] - [property $store cleanup_grace_period]}]
    set expired [db_le [db_col expires] [db_value $cutoff -type bigint]]
    set query [db_limit [db_where [db_select $table] [db_and [predicate $store {}] $expired]] $batch]
    set count 0
    db_transaction [dict get $store -connection] {
        foreach row [dict get [db_execute [dict get $store -connection] $query] rows] {
            set id [dict get $row id]
            set removed [dict get [db_execute [dict get $store -connection] [db_where [db_delete $table] \
                [db_and [predicate $store [dict create id $id]] $expired]]] rowcount]
            incr count $removed
            if {$removed && $table eq "web_user_registrations"} {revoke $store $id}
        }
    }
    return $count
}

# Remove expired sessions and challenges from the shared SQL session table.
proc ::web::user::prune_sessions {store {batch 500}} {prune_table $store tsession_sessions $batch}

# Remove expired pending credentials and their associated verification sessions.
proc ::web::user::prune_registrations {store {batch 500}} {prune_table $store web_user_registrations $batch}

# Remove elapsed rate-limit and failed-login counting buckets.
proc ::web::user::prune_limits {store {batch 500}} {prune_table $store web_user_limits $batch}

# Run one bounded maintenance pass and report counts for a host-owned scheduler.
proc ::web::user::prune {store {batch 500}} {
    dict create registrations [prune_registrations $store $batch] \
        sessions [prune_sessions $store $batch] limits [prune_limits $store $batch]
}
