#
# Copyright Jerily LTD. All Rights Reserved.
# SPDX-FileCopyrightText: 2026 Neofytos Dimitriou (neo@jerily.cy)
# SPDX-License-Identifier: MIT.
#

# Generate an unpredictable browser credential.
proc ::web::user::random_token {} {binary encode hex [::twebserver::random_bytes 32]}
# Accept 16 million of the 2^24 values to avoid bias when reducing to six digits.
proc ::web::user::verification_code {} {
    while {1} {
        set value [scan [binary encode hex [::twebserver::random_bytes 3]] %x]
        if {$value < 16000000} {return [format %06d [expr {$value % 1000000}]]}
    }
}
# Authenticate a value with tenant and purpose separation.
proc ::web::user::tag {store value purpose} {
    binary encode hex [::tink::mac::compute [dict get $store -mac] \
        [encoding convertto utf-8 [list web-user [dict get $store -tenant] $purpose $value]]]
}
# Encrypt a sensitive field with tenant-bound associated data.
proc ::web::user::seal {store value purpose} {
    binary encode base64 -maxlen 0 [::tink::aead::encrypt [dict get $store -aead] \
        [encoding convertto utf-8 $value] [encoding convertto utf-8 [list web-user [dict get $store -tenant] $purpose]]]
}
# Decrypt a field only for its original tenant and purpose.
proc ::web::user::unseal {store value purpose} {
    encoding convertfrom utf-8 [::tink::aead::decrypt [dict get $store -aead] \
        [binary decode base64 -strict $value] [encoding convertto utf-8 [list web-user [dict get $store -tenant] $purpose]]]
}
# The persistent site salt and normalized address form one unambiguous MAC input.
# Tenant and purpose binding come from tag; the MAC key remains host-owned.
proc ::web::user::email_key {store value} {
    tag $store [list [property $store email_hash_salt] [email $value]] email
}
# Passwords remain text until bcrypt-tcl converts them to standard UTF-8.
proc ::web::user::password_hash {value {config {}}} {
    set config [settings $config]
    set minimum [dict get $config password_min_length]
    set bytes [encoding convertto utf-8 $value]
    if {[string length $value] < $minimum || [string length $bytes] > 72 || [string first \x00 $value] >= 0} {
        fail 400 "Password must contain at least $minimum characters, at most 72 UTF-8 bytes, and no NUL characters."
    }
    package require bcrypt 2.0.1
    ::bcrypt::hashpw $value [::bcrypt::gensalt [dict get $config bcrypt_cost]]
}
# Decrypt the account-bound bcrypt hash only while checking a password. Bare
# hashes, corrupt ciphertext and values encrypted for another account fail closed.
proc ::web::user::password_ok {store user value} {
    set bytes [encoding convertto utf-8 $value]
    if {[string length $bytes] < 1 || [string length $bytes] > 72 || [string first \x00 $value] >= 0} {return 0}
    if {[catch {
        set hash [unseal $store [dict get $user password] [list password-hash [dict get $user id]]]
    }]} {return 0}
    # Fail closed for unsupported hashes and unreasonable stored costs.
    if {![regexp {^\$2[aby]\$(0[4-9]|1[0-6])\$[./A-Za-z0-9]{53}$} $hash]} {return 0}
    package require bcrypt 2.0.1
    ::bcrypt::checkpw $value $hash
}
# Verify a tenant- and purpose-bound MAC.
proc ::web::user::verify_tag {store digest value purpose} {
    if {![regexp {^(?:[0-9a-f]{2})+$} $digest]} {return 0}
    ::tink::mac::verify [dict get $store -mac] [binary decode hex $digest] \
        [encoding convertto utf-8 [list web-user [dict get $store -tenant] $purpose $value]]
}
# Find an acceptable authenticator step while rejecting replay.
proc ::web::user::totp_step {store secret code last} {
    set digits [property $store totp_digits]
    if {[string length $code] != $digits || ![regexp {^[0-9]+$} $code]} {return -1}
    set now [expr {[clock seconds] / [property $store totp_period]}]
    set window [property $store totp_window]
    set steps [list $now]
    for {set offset 1} {$offset <= $window} {incr offset} {
        lappend steps [expr {$now - $offset}] [expr {$now + $offset}]
    }
    foreach step $steps {
        if {$step < 0} {continue}
        # Use Tink's native MAC verification for the comparison.
        package require tmfa 1.1.2
        set expected [tag $store [::tmfa::get_hotp $secret $step $digits [property $store totp_algorithm]] totp-check]
        if {$step > $last && [verify_tag $store $expected $code totp-check]} {return $step}
    }
    return -1
}
