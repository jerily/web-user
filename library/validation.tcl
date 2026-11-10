# Load inline OpenAPI operations once per mount. Override only numeric limits
# from validated site configuration; keep the schemas as ordinary JSON files.
proc ::web::user::read_operations {filename overrides} {
    set document [::tjson::parse [read_text $filename]]
    try {
        dict for {path limits} $overrides {
            set node [lindex [::tjson::query $document $path] 0]
            dict for {name value} $limits {
                ::tjson::replace_item_in_object $node $name [list N $value]
            }
        }
        set operations {}
        foreach node [::tjson::get_child_items $document] {
            dict set operations [::tjson::get_string $node] [::tjson::to_json $node]
        }
        return $operations
    } finally {::tjson::destroy $document}
}
proc ::web::user::request_operations {store} {
    variable root
    set overrides {}
    foreach action {register reset} {
        set path [format {$.%s.requestBody.content['application/x-www-form-urlencoded'].schema.properties.password} $action]
        dict set overrides $path [dict create minLength [property $store password_min_length]]
    }
    read_operations [file join $root assets operations.json] $overrides
}
# Strict decoding happens first. topenapi then checks the action's required
# fields, lengths and enums. Do not expose validation diagnostics with credentials.
proc ::web::user::validate_form {request fields operation} {
    dict set request httpMethod [dict get $request method]
    set normalized [::topenapi::from_twebserver $request [dict create fields $fields]]
    set result [::topenapi::validate_request $normalized $operation]
    if {![dict get $result valid]} {fail 400 "Form fields are missing or invalid."}
}
