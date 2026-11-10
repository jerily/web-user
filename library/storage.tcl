proc ::web::user::options {defaults args} {
    if {[llength $args] % 2} {error "options must be name/value pairs"}
    foreach {key value} $args {
        if {![dict exists $defaults $key]} {error "unknown option: $key"}
        dict set defaults $key $value
    }
    return $defaults
}
proc ::web::user::environment {} {
    if {![info exists ::env(ENV)] || $::env(ENV) ni {LOCAL PROD}} {error "ENV must be LOCAL or PROD"}
    return $::env(ENV)
}
# The host owns and closes one connection per worker. Never fall back in PROD.
proc ::web::user::connect {config} {
    set c [options {sqlite_path {} postgresql {}} {*}$config]
    if {[environment] eq "LOCAL"} {
        if {[dict get $c sqlite_path] eq {}} {error "sqlite_path is required"}
        return [db_connect -dialect sqlite -database [dict get $c sqlite_path] -autobegin 0]
    }
    if {[dict get $c postgresql] eq {}} {error "postgresql connection options are required in PROD"}
    set pg [dict get $c postgresql]
    foreach {key value} $pg {
        if {$key ni {-host -port -database -user -password -sslmode -timeout -encoding}} {error "unsupported PostgreSQL option: $key"}
    }
    db_connect -dialect postgresql -autobegin 0 {*}$pg
}
proc ::web::user::initdb {connection} {
    foreach {table columns primary} {
        web_user_users {
            tenant text id text email_key text email text password text verified integer
            mfa_secret text last_step bigint revision integer created_at bigint
        } {tenant id}
        web_user_sessions {
            tenant text id text uid text kind text expires bigint code_tag text attempts integer pending_secret text
        } {tenant id}
        web_user_limits {tenant text id text hits integer expires bigint} {tenant id}
    } {
        set fields {}
        foreach {name type} $columns {dict set fields $name [dict create type $type not_null 1]}
        set definition [db_define_table $table $fields -primary_key $primary]
        if {$table eq "web_user_users"} {
            set definition [db_define_table $table $fields -primary_key $primary -unique {{tenant email_key}}]
        }
        db_create_table $connection $definition -if_not_exists 1
    }
}
proc ::web::user::create {args} {
    set c [options {-connection {} -tenant {} -aead {} -mac {}} {*}$args]
    foreach key {-connection -tenant -aead -mac} {if {[dict get $c $key] eq {}} {error "$key is required"}}
    dict set c -env [environment]
    # Validate both key handles before accepting any requests.
    set probe [seal $c probe check]
    if {[unseal $c $probe check] ne "probe"} {error "invalid encryption key"}
    tag $c probe check
    return $c
}
proc ::web::user::predicate {store where} {
    set terms [list [db_eq [db_col tenant] [db_value [dict get $store -tenant] -type text]]]
    dict for {key value} $where {lappend terms [db_eq [db_col $key] [db_value $value -type [column_type $key]]]}
    db_and {*}$terms
}
proc ::web::user::rows {store table {where {}}} {
    dict get [db_execute [dict get $store -connection] [db_where [db_select $table] [predicate $store $where]]] rows
}
proc ::web::user::one {store table where} {lindex [rows $store $table $where] 0}
proc ::web::user::insert {store table values} {
    dict set values tenant [dict get $store -tenant]
    db_execute [dict get $store -connection] [db_values [db_insert $table] [typed_values $values] -expressions]
}
proc ::web::user::update {store table where values} {
    dict get [db_execute [dict get $store -connection] [db_where [db_values [db_update $table] [typed_values $values] -expressions] [predicate $store $where]]] rowcount
}
proc ::web::user::remove {store table where} {
    dict get [db_execute [dict get $store -connection] [db_where [db_delete $table] [predicate $store $where]]] rowcount
}
proc ::web::user::user_by_id {store id} {one $store web_user_users [dict create id $id]}
# CAS serializes changes for a user across workers without dialect-specific SQL.
proc ::web::user::save_user {store user changes} {
    dict set changes revision [expr {[dict get $user revision] + 1}]
    if {[update $store web_user_users [dict create id [dict get $user id] revision [dict get $user revision]] $changes] != 1} {
        fail 409 "Account changed; retry the request."
    }
    dict merge $user $changes
}
proc ::web::user::prune {store} {
    foreach table {web_user_sessions web_user_limits} {
        db_execute [dict get $store -connection] [db_where [db_delete $table] \
            [db_and [predicate $store {}] [db_le [db_col expires] [db_value [clock seconds] -type bigint]]]]
    }
}

# TDBC must not infer byte arrays (hex/MAC values) as BLOBs for text columns.
proc ::web::user::column_type {name} {
    expr {$name in {verified last_step revision created_at expires attempts hits} ? "bigint" : "text"}
}
proc ::web::user::typed_values {values} {
    set result {}
    dict for {key value} $values {dict set result $key [db_value $value -type [column_type $key]]}
    return $result
}
