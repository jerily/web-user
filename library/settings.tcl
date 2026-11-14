#
# Copyright Jerily LTD. All Rights Reserved.
# SPDX-FileCopyrightText: 2026 Neofytos Dimitriou (neo@jerily.cy)
# SPDX-License-Identifier: MIT.
#

# Site policy is immutable for the lifetime of a store. Secrets are supplied by
# the host as registered Tink handles; none are compiled into package defaults.
proc ::web::user::settings {config} {
    set config [options {
        tenant {} aead {} mac {} email_hash_salt {}
        bcrypt_cost 12 password_min_length 15 collect_names false collect_display_name false collect_username false
        email_verification_required true verification_emails_enabled true resend_cooldown 60
        registration_captcha false captcha_ttl 300 captcha_length 6 captcha_letters true
        login_captcha_after 3 login_captcha_window 900
        totp_digits 6 totp_period 30 totp_algorithm SHA1 totp_window 1
        session_ttl 43200 persistent_session_ttl 2592000 code_ttl 900 challenge_ttl 600 cleanup_grace_period 3600
        throttle_window 900 browse_limit 120 post_limit 60 account_limit 10 challenge_limit 5
        form_max_bytes 32768
    } {*}$config]
    if {![string is boolean -strict [dict get $config collect_names]]} {error "collect_names must be a boolean"}
    dict set config collect_names [expr {!![dict get $config collect_names]}]
    foreach key {collect_display_name collect_username registration_captcha captcha_letters email_verification_required verification_emails_enabled} {
        if {![string is boolean -strict [dict get $config $key]]} {error "$key must be a boolean"}
        dict set config $key [expr {!![dict get $config $key]}]
    }
    foreach {key minimum maximum} {
        bcrypt_cost 4 16 password_min_length 6 72 captcha_ttl 1 3600 captcha_length 4 12
        login_captcha_after 0 100000 login_captcha_window 1 86400
        totp_period 1 120 totp_window 0 2 resend_cooldown 1 3600
        session_ttl 1 2592000 persistent_session_ttl 1 2592000 code_ttl 1 86400 challenge_ttl 1 86400
        cleanup_grace_period 0 2592000
        throttle_window 1 86400 browse_limit 1 100000 post_limit 1 100000
        account_limit 1 100000 challenge_limit 1 100 form_max_bytes 1024 1048576
    } {
        set value [dict get $config $key]
        if {![string is integer -strict $value] || $value < $minimum || $value > $maximum} {
            error "$key must be $minimum..$maximum"
        }
    }
    if {[dict get $config persistent_session_ttl] < [dict get $config session_ttl]} {
        error "persistent_session_ttl must be at least session_ttl"
    }
    if {[dict get $config totp_digits] ni {6 8}} {error "totp_digits must be 6 or 8"}
    dict set config totp_algorithm [string toupper [dict get $config totp_algorithm]]
    if {[dict get $config totp_algorithm] ni {SHA1 SHA256 SHA512}} {error "unsupported totp_algorithm"}
    return $config
}
# Read one validated account policy setting.
proc ::web::user::property {store name} {dict get $store -config $name}

# Read the same policy for provisioning, verification and LOCAL display.
proc ::web::user::totp_options {store} {
    list -digits [property $store totp_digits] -step [property $store totp_period] \
        -algorithm [property $store totp_algorithm]
}
# Generate a development authenticator code using site policy.
proc ::web::user::totp_code {store secret} {
    ::tmfa::get_totp $secret [property $store totp_digits] \
        [property $store totp_period] [property $store totp_algorithm]
}
