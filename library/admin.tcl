# Account administration reads only the current tenant after a permission check.
proc ::web::user::admin_query {request} {
    set result {page 1 sort last_login}
    if {[dict exists $request queryString] && [dict get $request queryString] ne {}} {
        set query [form [dict create headers {content-type application/x-www-form-urlencoded} \
            body [dict get $request queryString]] 2048]
        dict for {key value} $query {
            if {$key ni {page sort}} {fail 400 "Unknown query parameter."}
            dict set result $key $value
        }
    }
    if {![regexp {^[1-9][0-9]{0,6}$} [dict get $result page]]} {fail 400 "Invalid page number."}
    admin_sort_column [dict get $result sort]
    return $result
}
proc ::web::user::admin_sort_column {sort} {
    if {$sort ni {last_login last_visit registered}} {fail 400 "Invalid user order."}
    dict get {last_login last_login_at last_visit last_seen_at registered created_at} $sort
}

# Keep count and rows scoped identically. The timestamp/ID index bounds each page.
# Select only account fields needed for this screen, never password or MFA secrets.
proc ::web::user::admin_user_rows {store page {sort last_login}} {
    set column [admin_sort_column $sort]
    set connection [dict get $store -connection]
    set filter [predicate $store {}]
    set count [db_where [db_select web_user_users -columns [list [db_alias [db_count] total]]] $filter]
    set total [dict get [lindex [dict get [db_execute $connection $count] rows] 0] total]
    set pages [expr {max(1, ($total + 49) / 50)}]
    if {$page > $pages} {fail 404 "Page not found."}
    set columns {id email email_key username active verified created_at last_login_at last_seen_at last_email_login_at}
    lappend columns [db_alias [db_ne [db_col mfa_secret] [db_value {} -type text]] mfa_enabled]
    lappend columns [db_alias [db_ne [db_col password] [db_value {} -type text]] password_enabled]
    set query [db_order_by [db_where [db_select web_user_users -columns $columns] $filter] \
        [db_desc [db_col $column]] [db_desc [db_col id]]]
    set query [db_offset [db_limit $query 50] [expr {($page - 1) * 50}]]
    dict create items [dict get [db_execute $connection $query] rows] page $page pages $pages total $total sort $sort
}

# Fetch profile and configured group data only for the selected page, in batches.
proc ::web::user::admin_user_fields {store items} {
    if {$items eq {}} {return {}}
    set connection [dict get $store -connection]
    set ids [lmap row $items {db_value [dict get $row id] -type text}]
    set keys [lmap row $items {db_value [dict get $row email_key] -type text}]
    set profiles {}
    set query [db_where [db_select web_user_profiles] [db_and [predicate $store {}] [db_in [db_col id] $ids]]]
    foreach row [dict get [db_execute $connection $query] rows] {dict set profiles [dict get $row id] $row}
    set memberships {}
    set query [db_where [db_select web_user_group_members -columns {email_key group_name}] \
        [db_and [predicate $store {}] [db_in [db_col email_key] $keys]]]
    foreach row [dict get [db_execute $connection $query] rows] {
        dict lappend memberships [dict get $row email_key] [dict get $row group_name]
    }
    set identities {}
    set query [db_order_by [db_where [db_select web_user_identities -columns {uid provider created_at}] \
        [db_and [predicate $store {}] [db_in [db_col uid] $ids]]] [db_asc [db_col provider]]]
    foreach row [dict get [db_execute $connection $query] rows] {
        set fields [text_fields [dict create provider [string totitle [dict get $row provider]] \
            linked_datetime [clock format [dict get $row created_at] -gmt 1 -format {%Y-%m-%dT%H:%M:%SZ}] \
            linked_label [clock format [dict get $row created_at] -gmt 1 -format {%Y-%m-%d %H:%M UTC}]]]
        dict lappend identities [dict get $row uid] [list M $fields]
    }
    set result {}
    foreach row $items {
        set uid [dict get $row id]
        set names {first_name {} last_name {} display_name {}}
        if {[dict exists $profiles $uid]} {
            set profile [dict merge $names [dict get $profiles $uid]]
            foreach key {first_name last_name display_name} {
                if {[dict get $profile $key] ne {}} {
                    dict set names $key [unseal $store [dict get $profile $key] [list profile $uid $key]]
                }
            }
        }
        set fullName [string trim "[dict get $names first_name] [dict get $names last_name]"]
        if {$fullName eq {}} {set fullName [dict get $names display_name]}
        set groups {}
        if {[dict exists $memberships [dict get $row email_key]]} {
            set groups [lsort -unique [dict get $memberships [dict get $row email_key]]]
        }
        set username {}
        if {[dict exists $row username]} {set username [dict get $row username]}
        set fields [text_fields [dict create name $fullName username $username \
            email [unseal $store [dict get $row email] [list email $uid]] \
            registered_datetime [clock format [dict get $row created_at] -gmt 1 -format {%Y-%m-%dT%H:%M:%SZ}] \
            registered_label [clock format [dict get $row created_at] -gmt 1 -format {%Y-%m-%d %H:%M UTC}] \
            registered_date [clock format [dict get $row created_at] -gmt 1 -format {%Y-%m-%d}] \
            registered_time [clock format [dict get $row created_at] -gmt 1 -format {%H:%M UTC}]]]
        dict set fields groups [list L [lmap group $groups {list S $group}]]
        set linked {}
        if {[dict exists $identities $uid]} {set linked [dict get $identities $uid]}
        dict set fields identities [list L $linked]
        foreach {name column} {last_login last_login_at last_visit last_seen_at last_email_login last_email_login_at} {
            set seconds [dict get $row $column]
            set date {}
            set label {Not recorded}
            set day {}
            set time {}
            if {$seconds > 0} {
                set date [clock format $seconds -gmt 1 -format {%Y-%m-%dT%H:%M:%SZ}]
                set label [clock format $seconds -gmt 1 -format {%Y-%m-%d %H:%M UTC}]
                set day [clock format $seconds -gmt 1 -format {%Y-%m-%d}]
                set time [clock format $seconds -gmt 1 -format {%H:%M UTC}]
            }
            dict set fields ${name}_datetime [list S $date]
            dict set fields ${name}_label [list S $label]
            dict set fields ${name}_date [list S $day]
            dict set fields ${name}_time [list S $time]
        }
        foreach key {active verified mfa_enabled password_enabled} {dict set fields $key [list BOOL [expr {!![dict get $row $key]}]]}
        lappend result [list M $fields]
    }
    return $result
}

proc ::web::user::admin_users {config request context params} {
    try {
        set current [current_user $config $request $context]
        if {$current eq {}} {return [sign_in_redirect $config $request]}
        set store [dict get $config -store]
        if {![has_permission $store [dict get $current id] users.manage]} {fail 403 "User management permission is required."}
        set query [admin_query $request]
        set sort [dict get $query sort]
        set page [admin_user_rows $store [dict get $query page] $sort]
        set prefix [dict get $config -prefix]
        set fields [text_fields [dict create title {Manage users} brand [dict get $config -config title] \
            prefix $prefix assets [dict get $config -config assets_url] \
            page [dict get $page page] pages [dict get $page pages] total [dict get $page total] \
            sort $sort previous_url {} next_url {}]]
        if {[dict get $page page] > 1} {dict set fields previous_url [list S $prefix/admin/users?sort=$sort&page=[expr {[dict get $page page] - 1}]]}
        if {[dict get $page page] < [dict get $page pages]} {dict set fields next_url [list S $prefix/admin/users?sort=$sort&page=[expr {[dict get $page page] + 1}]]}
        set fields [dict merge [dict get $config -config properties] $fields]
        dict set fields users [list L [admin_user_fields $store [dict get $page items]]]
        dict set fields signed_in {BOOL 1}
        dict set fields editing {BOOL 0}
        dict set fields can_manage_users {BOOL 1}
        dict set fields admin_view {BOOL 1}
        set templates [dict get $config -templates]
        response 200 [::jinja2::render [dict get $templates admin-users.html.jinja] \
            [::tjson::typed_to_json [list M $fields]] -templates $templates -path admin-users.html.jinja]
    } trap {WEB USER} {message options} {
        response [lindex [dict get $options -errorcode] 2] $message {text/plain; charset=utf-8}
    }
}

proc ::web::user::admin_stylesheet {request context params} {
    variable root
    set result [response 200 [read_text [file join $root assets admin.css]] {text/css; charset=utf-8}]
    dict set result headers cache-control {public, max-age=3600}
    return $result
}
