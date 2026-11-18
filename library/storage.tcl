#
# Copyright Jerily LTD. All Rights Reserved.
# SPDX-FileCopyrightText: 2026 Neofytos Dimitriou (neo@jerily.cy)
# SPDX-License-Identifier: MIT.
#

# Merge supported options with their defaults.
proc ::web::user::options {defaults args} {
    if {[llength $args] % 2} {error "options must be name/value pairs"}
    foreach {key value} $args {
        if {![dict exists $defaults $key]} {error "unknown option: $key"}
        dict set defaults $key $value
    }
    return $defaults
}
# Require an explicit supported deployment environment.
proc ::web::user::environment {} {
    if {![info exists ::env(ENV)] || $::env(ENV) ni {LOCAL PROD}} {error "ENV must be LOCAL or PROD"}
    return $::env(ENV)
}
# The host owns and closes one connection per worker. Never fall back in PROD.
proc ::web::user::connect {config} {
    set config [options {sqlite_path {} postgresql {}} {*}$config]
    if {[environment] eq "LOCAL"} {
        if {[dict get $config sqlite_path] eq {}} {error "sqlite_path is required"}
        return [db_connect -dialect sqlite -database [dict get $config sqlite_path] -autobegin 0]
    }
    if {[dict get $config postgresql] eq {}} {error "postgresql connection options are required in PROD"}
    set pg [dict get $config postgresql]
    foreach {key value} $pg {
        if {$key ni {-host -port -database -user -password -sslmode -timeout -encoding}} {error "unsupported PostgreSQL option: $key"}
    }
    db_connect -dialect postgresql -autobegin 0 {*}$pg
}
# Initialize the selected session store and account schema.
proc ::web::user::initdb {connection} {
    variable root
    set backend [session_backend]
    ${backend}::initdb $connection
    db_apply_schema $connection [file join $root sql schema.json] -additive true
    migrate_registrations $connection
    package require pure-tcl-oauth2-core 0.1.0
    ::oauth2::store::initdb $connection
}
# Validate account policy and borrow the host SQL connection.
proc ::web::user::create {args} {
    set config [options {-connection {} -config {}} {*}$args]
    set settings [settings [dict get $config -config]]
    if {[dict get $settings registration_captcha] || [dict get $settings login_captcha_after] > 0} {package require tcaptcha 1.0.0}
    foreach key {tenant aead mac} {
        dict set config -$key [dict get $settings $key]
    }
    if {[string trim [dict get $settings email_hash_salt]] eq {}} {error "email_hash_salt is required"}
    dict set config -config $settings
    foreach key {-connection -tenant -aead -mac} {if {[dict get $config $key] eq {}} {error "$key is required"}}
    dict set config -env [environment]
    set dialect [expr {[dict get $config -env] eq "LOCAL" ? "sqlite" : "postgresql"}]
    if {[db_dialect [dict get $config -connection]] ne $dialect} {error "session store requires a $dialect connection"}
    set backend [session_backend]
    dict set config -sessions [${backend}::create -connection [dict get $config -connection] -tenant [dict get $config -tenant]]
    # Validate both key handles before accepting any requests.
    set probe [seal $config probe check]
    if {[unseal $config $probe check] ne "probe"} {error "invalid encryption key"}
    tag $config probe check
    return $config
}
# Build a typed tenant-scoped SQL filter.
proc ::web::user::predicate {store where} {
    set terms [list [db_eq [db_col tenant] [db_value [dict get $store -tenant] -type text]]]
    dict for {key value} $where {lappend terms [db_eq [db_col $key] [db_value $value -type [column_type $key]]]}
    db_and {*}$terms
}
# Read tenant-scoped rows and normalize nullable profile fields.
proc ::web::user::rows {store table {where {}}} {
    set result [dict get [db_execute [dict get $store -connection] [db_where [db_select $table] [predicate $store $where]]] rows]
    set defaults {}
    if {$table in {web_user_users web_user_registrations}} {dict set defaults username {}}
    if {$table in {web_user_profiles web_user_registrations}} {dict set defaults display_name {}}
    lmap row $result {dict merge $defaults $row}
}
# Return the first matching tenant-scoped row.
proc ::web::user::one {store table where} {lindex [rows $store $table $where] 0}
# Insert a row with explicit tenant and SQL parameter types.
proc ::web::user::insert {store table values} {
    dict set values tenant [dict get $store -tenant]
    db_execute [dict get $store -connection] [db_values [db_insert $table] [typed_values $values] -expressions]
}
# Update matching tenant-scoped rows and return the affected count.
proc ::web::user::update {store table where values} {
    dict get [db_execute [dict get $store -connection] [db_where [db_values [db_update $table] [typed_values $values] -expressions] [predicate $store $where]]] rowcount
}
# Delete matching tenant-scoped rows and return the affected count.
proc ::web::user::remove {store table where} {
    dict get [db_execute [dict get $store -connection] [db_where [db_delete $table] [predicate $store $where]]] rowcount
}
# Find an account by its tenant-scoped identifier.
proc ::web::user::user_by_id {store id} {one $store web_user_users [dict create id $id]}
# Find an account through the keyed normalized-email index.
proc ::web::user::user_by_email {store address} {
    one $store web_user_users [dict create email_key [email_key $store $address]]
}
# CAS serializes changes for a user across workers without dialect-specific SQL.
proc ::web::user::save_user {store user changes} {
    dict set changes revision [expr {[dict get $user revision] + 1}]
    if {[update $store web_user_users [dict create id [dict get $user id] revision [dict get $user revision]] $changes] != 1} {
        fail 409 "Account changed; retry the request."
    }
    dict merge $user $changes
}
# TDBC must not infer byte arrays (hex/MAC values) as BLOBs for text columns.
proc ::web::user::column_type {name} {
    expr {$name in {active verified last_step revision created_at last_login_at last_seen_at last_email_login_at expires applied_at attempts hits} ? "bigint" : "text"}
}
# Bind SQL values explicitly, preserving nullable profile fields.
proc ::web::user::typed_values {values} {
    set result {}
    dict for {key value} $values {
        if {$key in {username display_name} && $value eq {}} {dict set result $key [db_null]} else {
            dict set result $key [db_value $value -type [column_type $key]]
        }
    }
    return $result
}
