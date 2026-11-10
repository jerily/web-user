# Widget callback: properties request context -> trusted, escaped HTML fragment.
# Bind the mount and widget name in the host; consumers do not load our templates.
proc ::web::user::widget {config name properties request context} {
    if {$name ne "profile"} {error "unknown web-user widget: $name"}
    set properties [options {user_id {}} {*}$properties]
    set profile [public_profile [dict get $config -store] [dict get $properties user_id]]
    set templates [dict get $config -templates]
    ::jinja2::render [dict get $templates profile.html.jinja] \
        [::tjson::typed_to_json [list M [text_fields $profile]]] \
        -templates $templates -path profile.html.jinja
}
