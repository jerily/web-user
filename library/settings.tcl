# Site policy is immutable for the lifetime of a store. Secrets are supplied by
# the host as registered Tink handles; none are compiled into package defaults.
proc ::web::user::settings {config} {
    set config [options {
        tenant {} aead {} mac {}
        bcrypt_cost 12 password_min_length 15
        totp_digits 6 totp_period 30 totp_algorithm SHA1 totp_window 1
        session_ttl 43200 code_ttl 900 challenge_ttl 600
        throttle_window 900 browse_limit 120 post_limit 60 account_limit 10 challenge_limit 5
        form_max_bytes 32768
    } {*}$config]
    foreach {key minimum maximum} {
        bcrypt_cost 4 16 password_min_length 6 72
        totp_period 1 120 totp_window 0 2
        session_ttl 1 2592000 code_ttl 1 86400 challenge_ttl 1 86400
        throttle_window 1 86400 browse_limit 1 100000 post_limit 1 100000
        account_limit 1 100000 challenge_limit 1 100 form_max_bytes 1024 1048576
    } {
        set value [dict get $config $key]
        if {![string is integer -strict $value] || $value < $minimum || $value > $maximum} {
            error "$key must be $minimum..$maximum"
        }
    }
    if {[dict get $config totp_digits] ni {6 8}} {error "totp_digits must be 6 or 8"}
    dict set config totp_algorithm [string toupper [dict get $config totp_algorithm]]
    if {[dict get $config totp_algorithm] ni {SHA1 SHA256 SHA512}} {error "unsupported totp_algorithm"}
    return $config
}
proc ::web::user::property {store name} {dict get $store -config $name}

# Read the same policy for provisioning, verification and LOCAL display.
proc ::web::user::totp_options {store} {
    list -digits [property $store totp_digits] -step [property $store totp_period] \
        -algorithm [property $store totp_algorithm]
}
proc ::web::user::totp_code {store secret} {
    ::tmfa::get_totp $secret [property $store totp_digits] \
        [property $store totp_period] [property $store totp_algorithm]
}
