# Configuration is authoritative for one tenant. Membership uses the same keyed
# email index as accounts, so it also covers people who register after a sync.

# Explicit initialization/maintenance API. Validate everything before changing
# rows, then replace the tenant's membership and grants atomically. No plaintext
# email addresses are stored in the authorization tables.
proc ::web::user::sync_access {store groups permissions} {
    set config [access_config $groups $permissions]
    set memberships {}
    dict for {group addresses} [dict get $config groups] {
        foreach address $addresses {
            lappend memberships [dict create group_name $group email_key [email_key $store $address]]
        }
    }
    set grants {}
    dict for {group names} [dict get $config permissions] {
        foreach name $names {lappend grants [dict create group_name $group permission $name]}
    }
    db_transaction [dict get $store -connection] {
        foreach table {web_user_group_permissions web_user_group_members web_user_groups} {remove $store $table {}}
        foreach group [dict keys [dict get $config groups]] {insert $store web_user_groups [dict create group_name $group]}
        foreach membership $memberships {insert $store web_user_group_members $membership}
        foreach grant $grants {insert $store web_user_group_permissions $grant}
    }
    dict create groups [dict size [dict get $config groups]] memberships [llength $memberships] permissions [llength $grants]
}

# Read current account state and grants, rather than trusting permissions copied
# into a session. Revocation therefore takes effect on the next request.
proc ::web::user::groups {store uid} {
    if {$uid eq {}} {return {}}
    set user [user_by_id $store $uid]
    if {$user eq {} || ![dict get $user active] || ![dict get $user verified]} {return {}}
    set result {}
    foreach row [rows $store web_user_group_members [dict create email_key [dict get $user email_key]]] {
        lappend result [dict get $row group_name]
    }
    return [lsort -unique $result]
}

proc ::web::user::permissions {store uid} {
    set result {}
    foreach group [groups $store $uid] {
        foreach row [rows $store web_user_group_permissions [dict create group_name $group]] {
            lappend result [dict get $row permission]
        }
    }
    return [lsort -unique $result]
}

proc ::web::user::has_permission {store uid permission} {
    expr {$permission in [permissions $store $uid]}
}
