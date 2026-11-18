# SPDX-License-Identifier: MIT
# Google identity is keyed by verified issuer and subject, never by email.
proc ::web::user::mount_store {config} {
    set secret [options {aead_keyset {} mac_keyset {} email_hash_salt {} google_client_secret {}} {*}[dict get $config -secret_config]]
    dict set config -secret_config $secret
    dict set config -owned-keys {}
    if {[dict get $config -connection] eq {}} {
        if {[dict get $config -policy] ne {}} {error "-policy requires -connection"}
        foreach name {aead_keyset mac_keyset email_hash_salt} {
            if {[dict get $secret $name] ne {}} {error "Private account keys require -connection; omit -store"}
        }
        return $config
    }
    if {[dict get $config -store] ne {}} {error "Use either -store or -connection with private keys"}
    set policy [dict get $config -policy]
    foreach name {aead mac email_hash_salt aead_keyset mac_keyset} {
        if {[dict exists $policy $name]} {error "Account cryptographic settings belong in -secret_config"}
    }
    foreach name {aead_keyset mac_keyset email_hash_salt} {
        if {[string trim [dict get $secret $name]] eq {}} {error "-secret_config $name is required"}
    }
    try {
        foreach {name key} {aead aead_keyset mac mac_keyset} {
            set handle [::tink::register_keyset [dict get $secret $key]]
            dict lappend config -owned-keys $handle
            dict set policy $name $handle
        }
        dict set policy email_hash_salt [dict get $secret email_hash_salt]
        dict set config -store [create -connection [dict get $config -connection] -config $policy]
    } on error {message opts} {release $config; return -options $opts $message}
    return $config
}
proc ::web::user::google_configure {config} {
    set settings [dict get $config -config]
    set secret [dict get $config -secret_config]
    set enabled [dict get $settings google_enabled]
    if {$enabled eq {}} {set enabled false}
    if {![string is boolean -strict $enabled]} {error "google_enabled must be boolean"}
    dict set config -config google_enabled $enabled
    if {!$enabled} {return $config}
    foreach name {google_client_id google_redirect_uri} {
        if {[dict get $settings $name] eq {}} {error "$name is required when Google Login is enabled"}
    }
    if {[dict get $secret google_client_secret] eq {}} {error "-secret_config google_client_secret is required"}
    if {[dict get $settings google_redirect_uri] ne "[dict get $settings origin][dict get $config -prefix]/google/callback"} {
        error "google_redirect_uri must match origin, mount prefix and /google/callback exactly"
    }
    package require pure-tcl-oauth2-client 0.1.0
    set store [dict get $config -store]
    set transactions [::oauth2::store::sql [dict get $store -connection] [list web-user-google [dict get $store -tenant]]]
    try {
        set client [::oauth2::client::create -provider google -client_id [dict get $settings google_client_id] \
            -client_secret [dict get $secret google_client_secret] -redirect_uri [dict get $settings google_redirect_uri] \
            -transaction_store $transactions -aead [dict get $store -aead] -allow_http [expr {[dict get $store -env] eq "LOCAL"}]]
    } on error {message opts} {$transactions destroy; return -options $opts $message}
    dict set config -google-client $client
    dict set config -google-store $transactions
    return $config
}
# Call after removing the mounted routes, before destroying borrowed keys/connection.
proc ::web::user::release {config} {
    foreach name {-google-client -google-store} {
        if {[dict exists $config $name] && [info commands [dict get $config $name]] ne {}} {[dict get $config $name] destroy}
    }
    if {[dict exists $config -owned-keys]} {
        foreach handle [dict get $config -owned-keys] {catch {::tink::unregister_keyset $handle}}
    }
}
proc ::web::user::google_identity {store subject} {
    tag $store [list https://accounts.google.com $subject] oauth-identity
}
proc ::web::user::google_linked {store uid} {
    expr {[one $store web_user_identities [dict create uid $uid provider google]] ne {}}
}
proc ::web::user::has_password {user} {expr {[dict get $user password] ne {}}}
proc ::web::user::field_or_empty {fields name} {expr {[dict exists $fields $name] ? [dict get $fields $name] : {}}}
# Relax only the password field for a known passwordless authenticated account.
# The service still requires its recent provider proof (and OTP where applicable).
proc ::web::user::passwordless_operation {operation view} {
    set document [::tjson::parse $operation]
    try {
        set schema [lindex [::tjson::query $document {$.requestBody.content['application/x-www-form-urlencoded'].schema}] 0]
        set required {}
        foreach entry [::tjson::get_child_items [::tjson::get_object_item $schema required]] {
            set name [::tjson::get_valuestring $entry]
            if {$name ni {password current_password}} {lappend required [list S $name]}
        }
        ::tjson::replace_item_in_object $schema required [list L $required]
        if {$view eq "two-factor/setup"} {
            set begin [lindex [::tjson::query $schema {$.oneOf[0]}] 0]
            ::tjson::replace_item_in_object $begin required {L {}}
        }
        return [::tjson::to_json $document]
    } finally {::tjson::destroy $document}
}
# Passwordless accounts require email or Google proof from the last five minutes.
# A pending MFA challenge is not an authenticated session and cannot use this proof.
proc ::web::user::confirm_credentials {store row user password} {
    if {[has_password $user]} {
        if {![password_ok $store $user $password]} {fail 401 "Invalid current password."}
        return
    }
    if {[dict get $row kind] eq "auth" && [dict get $user verified] &&
        [dict exists $row email_verified_at] && [dict get $row email_verified_at] >= [clock seconds]-300} {return}
    if {[dict get $row kind] ne "auth" || ![dict exists $row google_verified_at] ||
        [dict get $row google_verified_at] < [clock seconds]-300 ||
        ![google_linked $store [dict get $user id]]} {
        fail 401 "Sign in again with an email code or confirm your linked Google account, then try again."
    }
}
proc ::web::user::google_mark_session {store token when} {
    request_mutating
    set row [session $store $token]
    if {[::tsession::sql::update [dict get $store -sessions] [dict get $row id] [dict create google_verified_at $when]] != 1} {
        fail 409 "Session changed; sign in again."
    }
}
# Perform this only inside the account transaction, after the client verified JWT.
proc ::web::user::google_complete {config row identity intent uid} {
    set store [dict get $config -store]
    if {[dict get $identity issuer] ne "https://accounts.google.com"} {fail 401 "Unexpected identity provider."}
    set id [google_identity $store [dict get $identity subject]]
    set linked [one $store web_user_identities [dict create id $id]]
    if {$intent in {link reauth}} {
        set user [require_user $store $row]
        if {[dict get $user id] ne $uid} {fail 401 "Account session changed. Start again."}
        if {$intent eq "reauth" && ($linked eq {} || [dict get $linked uid] ne $uid)} {fail 401 "Choose the Google account already linked to this account."}
        if {$intent eq "link"} {
            if {$linked ne {} || [google_linked $store $uid]} {fail 409 "A Google account is already linked. Unlink it first."}
            save_user $store $user {}
            insert $store web_user_identities [dict create id $id uid $uid provider google created_at [clock seconds]]
            return [rotate $store $row auth $uid {} [session_persistent $row]]
        }
    } else {
        if {[authenticated $store $row] ne {}} {fail 409 "Sign out before switching accounts."}
        if {$linked ne {}} {
            set user [user_by_id $store [dict get $linked uid]]
        } else {
            set claims [dict get $identity claims]
            if {![::oauth2::core::value $claims email_verified BOOL false]} {fail 403 "Google must verify your email before registration."}
            set address [email [::oauth2::core::claim_string $claims email]]
            if {[user_by_email $store $address] ne {}} {fail 409 "An account already uses this email. Sign in to that account and link Google from the account page."}
            set uid user_[::ksuid::generate_ksuid]
            set user [dict create id $uid email_key [email_key $store $address] email [seal $store $address [list email $uid]] \
                password {} verified 1 active 1 mfa_secret {} last_step -1 revision 0 created_at [clock seconds] username {}]
            insert_account $store $user
            insert $store web_user_identities [dict create id $id uid $uid provider google created_at [clock seconds]]
            set names {}
            foreach {name claim setting maximum} {first_name given_name collect_names 100 last_name family_name collect_names 100 display_name name collect_display_name 80} {
                if {[property $store $setting]} {
                    set value [::oauth2::core::claim_string $claims $claim {}]
                    if {[string length $value] <= $maximum && ![regexp {[\x00-\x1f\x7f]} $value]} {dict set names $name $value}
                }
            }
            save_profile $store $uid $names
        }
    }
    if {$user eq {} || ![dict get $user active]} {fail 403 "This account is unavailable."}
    set uid [dict get $user id]
    set kind [expr {[dict get $user mfa_secret] eq {} ? "auth" : "two-factor"}]
    set changes {}
    if {$kind eq "auth"} {set changes [dict create last_login_at [clock seconds] last_seen_at [clock seconds]]}
    save_user $store $user $changes
    set token [rotate $store $row $kind $uid {} [session_persistent $row]]
    google_mark_session $store $token [clock seconds]
    return $token
}
# Keep password confirmation on its own authenticated page.
proc ::web::user::google_link {config request context params} {
    handle $config google/link {} 0 $request $context
}
proc ::web::user::google_start {config request context params} {
    set store [dict get $config -store]
    set token [cookie_token $config $request]
    try {
        set fields [form $request [property $store form_max_bytes]]
        set row [session $store $token]
        if {$row eq {} || ![dict exists $fields csrf] || ![csrf $config verify $request $context [dict get $fields csrf]]} {fail 403 "Invalid CSRF token. Reload the account page."}
        throttle $store [list google [peer $context]] [property $store post_limit]
        set intent [expr {[dict exists $fields intent] ? [dict get $fields intent] : "login"}]
        if {$intent ni {login link reauth}} {fail 400 "Invalid Google action."}
        set uid {}
        if {$intent ne "login"} {
            set user [require_user $store $row]; set uid [dict get $user id]
            if {$intent eq "link"} {
                confirm_credentials $store $row $user [field_or_empty $fields password]
            }
        }
        set target [requested_return_to $request]
        if {$target eq {}} {set target [dict get $config -prefix]}
        set start [[dict get $config -google-client] start -browser_session $token -return_to $target -prompt select_account]
        [dict get $config -google-store] put account_flow [::oauth2::core::digest [dict get $start state]] \
            [dict create intent $intent uid $uid browser [::oauth2::core::digest $token] revision [expr {$uid eq {} ? -1 : [dict get $user revision]}]] [expr {[clock seconds]+600}]
        return [redirect [dict get $start authorization_url]]
    } trap {WEB USER} {message opts} {
        return [response [lindex [dict get $opts -errorcode] 2] $message text/plain]
    } on error {message opts} {return [response 400 {Google sign-in could not start. Reload the account page and try again.} text/plain]}
}
proc ::web::user::google_callback {config request context params} {
    request_mutating
    set store [dict get $config -store]
    set token [cookie_token $config $request]
    try {
        set row [session $store $token]
        if {$row eq {}} {fail 401 "Login session expired. Start again."}
        throttle $store [list google-callback [peer $context]] [property $store post_limit]
        set parameters [::oauth2::core::form_decode [dict get $request queryString]]
        set identity [[dict get $config -google-client] callback $parameters -browser_session $token]
        set transactions [dict get $config -google-store]
        set id [::oauth2::core::digest [dict get $parameters state]]
        db_transaction [dict get $store -connection] {
            set flow [$transactions get account_flow $id [clock seconds]]
            if {$flow eq {} || [dict get $flow data browser] ne [::oauth2::core::digest $token] || ![$transactions delete account_flow $id $flow]} {fail 401 "Login transaction expired. Start again."}
            set row [session $store $token]
            if {$row eq {}} {fail 401 "Account session changed. Start again."}
            set intent [dict get $flow data intent]; set uid [dict get $flow data uid]
            if {$intent eq "link"} {
                set user [require_user $store $row]
                if {[dict get $user revision] != [dict get $flow data revision]} {fail 409 "Account changed. Start linking again."}
            }
            set token [google_complete $config $row $identity $intent $uid]
        }
        set target [safe_return_to [dict get $identity return_to]]
        if {$target eq {}} {set target [dict get $config -prefix]}
        if {[dict get [session $store $token] kind] eq "two-factor"} {set target [dict get $config -prefix]/two-factor[return_query $target]}
        return [set_cookie $config [redirect $target] $token]
    } trap {WEB USER} {message opts} {
        return [response [lindex [dict get $opts -errorcode] 2] $message text/plain]
    } on error {message opts} {return [response 400 {Google sign-in was not completed. Return to the login page and try again.} text/plain]}
}
proc ::web::user::google_unlink {config request context params} {
    set store [dict get $config -store]
    set token [cookie_token $config $request]
    try {
        set fields [form $request]; set row [session $store $token]
        if {$row eq {} || ![dict exists $fields csrf] || ![csrf $config verify $request $context [dict get $fields csrf]]} {fail 403 "Invalid CSRF token."}
        throttle $store [list google-unlink [peer $context]] [property $store post_limit]
        db_transaction [dict get $store -connection] {
            set user [require_user $store [session $store $token]]
            if {![has_password $user]} {fail 409 "Set a password before removing your only sign-in method."}
            if {![dict exists $fields password]} {fail 401 "Confirm your password."}
            confirm_credentials $store $row $user [dict get $fields password]
            save_user $store $user {}
            set uid [dict get $user id]
            remove $store web_user_identities [dict create uid $uid provider google]
            revoke $store $uid
            set token [new_session $store auth $uid {} [session_persistent $row]]
        }
        return [set_cookie $config [redirect [dict get $config -prefix]] $token]
    } trap {WEB USER} {message opts} {return [response [lindex [dict get $opts -errorcode] 2] $message text/plain]}
}
