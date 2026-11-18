# Re-encrypt one field for the same identity under its prefixed identifier.
proc ::web::user::rekey_identity_field {store value before after} {
    if {$value eq {}} {return {}}
    seal $store [unseal $store $value $before] $after
}

# Explicit, tenant-scoped maintenance. Re-running finds no bare IDs to change.
# Session credentials stay unchanged; their subject and encrypted MFA state move
# with the account. A failure rolls back every identity and session in this run.
proc ::web::user::migrate_user_ids {store} {
    set counts {users 0 registrations 0 profiles 0 sessions 0}
    db_transaction [dict get $store -connection] {
        set mappings {}
        foreach table {web_user_users web_user_registrations} {
            foreach row [rows $store $table] {
                set old [dict get $row id]
                if {[regexp {^user_[0-9A-Za-z]{27}$} $old]} {continue}
                if {![regexp {^[0-9A-Za-z]{27}$} $old]} {error "Cannot migrate an invalid account identifier"}
                dict set mappings $old user_$old
            }
        }
        # Detect collisions before replacing any record.
        dict for {old new} $mappings {
            foreach table {web_user_users web_user_registrations web_user_profiles} {
                if {[one $store $table [dict create id $new]] ne {}} {error "Prefixed account identifier already exists"}
            }
        }
        dict for {old new} $mappings {
            foreach {table counter} {web_user_users users web_user_registrations registrations} {
                set row [one $store $table [dict create id $old]]
                if {$row eq {}} {continue}
                set changes [dict create id $new]
                foreach {field purpose} {email email password password-hash mfa_secret mfa} {
                    if {[dict exists $row $field]} {
                        dict set changes $field [rekey_identity_field $store [dict get $row $field] \
                            [list $purpose $old] [list $purpose $new]]
                    }
                }
                foreach field {first_name last_name display_name} {
                    if {[dict exists $row $field]} {
                        dict set changes $field [rekey_identity_field $store [dict get $row $field] \
                            [list profile $old $field] [list profile $new $field]]
                    }
                }
                set where [dict create id $old]
                if {$counter eq "users"} {
                    dict set where revision [dict get $row revision]
                    dict set changes revision [expr {[dict get $row revision] + 1}]
                }
                if {[update $store $table $where $changes] != 1} {error "Account changed during ID migration"}
                dict incr counts $counter
            }
            update $store web_user_identities [dict create uid $old] [dict create uid $new]
            set profile [one $store web_user_profiles [dict create id $old]]
            if {$profile ne {}} {
                set changes [dict create id $new]
                foreach field {first_name last_name display_name} {
                    dict set changes $field [rekey_identity_field $store [dict get $profile $field] \
                        [list profile $old $field] [list profile $new $field]]
                }
                if {[update $store web_user_profiles [dict create id $old] $changes] != 1} {error "Profile changed during ID migration"}
                dict incr counts profiles
            }
            foreach session [rows $store tsession_sessions [dict create subject $old]] {
                set data [dict get $session data]
                if {![dict exists $data uid] || [dict get $data uid] ne $old} {error "Session identity does not match its subject"}
                dict set data uid $new
                if {[dict exists $data pending_secret]} {
                    dict set data pending_secret [rekey_identity_field $store [dict get $data pending_secret] \
                        [list mfa $old] [list mfa $new]]
                }
                set revision [dict get $session revision]
                set changes [dict create subject $new data $data revision [expr {$revision + 1}]]
                if {[update $store tsession_sessions [dict create id [dict get $session id] revision $revision] $changes] != 1} {
                    error "Session changed during ID migration"
                }
                dict incr counts sessions
            }
        }
    }
    return $counts
}
