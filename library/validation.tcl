#
# Copyright Jerily LTD. All Rights Reserved.
# SPDX-FileCopyrightText: 2026 Neofytos Dimitriou (neo@jerily.cy)
# SPDX-License-Identifier: MIT.
#

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
# Adjust form schemas to the configured profile fields.
proc ::web::user::request_operations {store} {
    variable root
    set operations [read_operations [file join $root schemas operations.json] {}]
    foreach view {register profile} {
        set document [::tjson::parse [dict get $operations $view]]
        try {
            set schema [lindex [::tjson::query $document {$.requestBody.content['application/x-www-form-urlencoded'].schema}] 0]
            set properties [::tjson::get_object_item $schema properties]
            set required {{S csrf}}
            if {$view eq "register"} {lappend required {S email} {S password}}
            foreach {key setting} {first_name collect_names last_name collect_names display_name collect_display_name username collect_username} {
                if {[property $store $setting]} {
                    if {$key ne "display_name"} {lappend required [list S $key]}
                } else {::tjson::delete_item_from_object $properties $key}
            }
            ::tjson::replace_item_in_object $schema required [list L $required]
            dict set operations $view [::tjson::to_json $document]
        } finally {::tjson::destroy $document}
    }
    if {![property $store collect_username]} {
        set document [::tjson::parse [dict get $operations verify]]
        try {
            set properties [lindex [::tjson::query $document {$.requestBody.content['application/x-www-form-urlencoded'].schema.properties}] 0]
            ::tjson::delete_item_from_object $properties username
            dict set operations verify [::tjson::to_json $document]
        } finally {::tjson::destroy $document}
    }
    return $operations
}
# Strict decoding happens first. topenapi then checks the action's required
# fields, lengths and enums. Do not expose validation diagnostics with credentials.
proc ::web::user::validate_form {request fields operation} {
    dict set request httpMethod [dict get $request method]
    set normalized [::topenapi::from_twebserver $request [dict create fields $fields]]
    set result [::topenapi::validate_request $normalized $operation]
    if {![dict get $result valid]} {fail 400 "Form fields are missing or invalid."}
}
