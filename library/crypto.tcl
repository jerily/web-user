proc ::web::user::random_token {} {binary encode hex [::twebserver::random_bytes 32]}
proc ::web::user::tag {store value purpose} {
    binary encode hex [::tink::mac::compute [dict get $store -mac] \
        [encoding convertto utf-8 [list web-user [dict get $store -tenant] $purpose $value]]]
}
proc ::web::user::seal {store value purpose} {
    binary encode base64 -maxlen 0 [::tink::aead::encrypt [dict get $store -aead] \
        [encoding convertto utf-8 $value] [encoding convertto utf-8 [list web-user [dict get $store -tenant] $purpose]]]
}
proc ::web::user::unseal {store value purpose} {
    encoding convertfrom utf-8 [::tink::aead::decrypt [dict get $store -aead] \
        [binary decode base64 -strict $value] [encoding convertto utf-8 [list web-user [dict get $store -tenant] $purpose]]]
}
proc ::web::user::email {value} {
    set value [string tolower [string trim $value]]
    if {[string length $value] > 254 || ![regexp {^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$} $value]} {
        fail 400 "Enter a valid email address."
    }
    return $value
}
# Passwords remain text until bcrypt-tcl converts them to standard UTF-8.
proc ::web::user::password_hash {value} {
    set bytes [encoding convertto utf-8 $value]
    if {[string length $value] < 15 || [string length $bytes] > 72 || [string first \x00 $value] >= 0} {
        fail 400 "Password must contain at least 15 characters, at most 72 UTF-8 bytes, and no NUL characters."
    }
    ::bcrypt::hashpw $value [::bcrypt::gensalt 12]
}
proc ::web::user::password_ok {user value} {
    set bytes [encoding convertto utf-8 $value]
    if {[string length $bytes] < 1 || [string length $bytes] > 72 || [string first \x00 $value] >= 0} {return 0}
    set hash [dict get $user password]
    # Fail closed for obsolete/unsupported hashes and unreasonable stored costs.
    if {![regexp {^\$2[aby]\$(0[4-9]|1[0-6])\$[./A-Za-z0-9]{53}$} $hash]} {return 0}
    ::bcrypt::checkpw $value $hash
}
proc ::web::user::verify_tag {store digest value purpose} {
    if {![regexp {^(?:[0-9a-f]{2})+$} $digest]} {return 0}
    ::tink::mac::verify [dict get $store -mac] [binary decode hex $digest] \
        [encoding convertto utf-8 [list web-user [dict get $store -tenant] $purpose $value]]
}
proc ::web::user::totp_step {store secret code last} {
    if {![regexp {^[0-9]{6}$} $code]} {return -1}
    set now [expr {[clock seconds] / 30}]
    foreach step [list $now [expr {$now - 1}] [expr {$now + 1}]] {
        # Use Tink's native MAC verification for the comparison.
        set expected [tag $store [::tmfa::get_hotp $secret $step 6 SHA1] totp-check]
        if {$step > $last && [verify_tag $store $expected $code totp-check]} {return $step}
    }
    return -1
}
