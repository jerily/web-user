proc ::web::user::random_token {} {binary encode hex [::tink::random_bytes 32]}
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
proc ::web::user::password_hash {value} {
    set bytes [encoding convertto utf-8 $value]
    if {[string length $value] < 15 || [string length $bytes] > 1024} {fail 400 "Password must contain at least 15 characters and at most 1024 UTF-8 bytes."}
    ::tink::password::hash $bytes
}
proc ::web::user::password_ok {user value} {
    set bytes [encoding convertto utf-8 $value]
    if {[string length $bytes] < 1 || [string length $bytes] > 1024} {return 0}
    ::tink::password::verify $bytes [dict get $user password]
}
proc ::web::user::totp_step {secret code last} {
    if {![regexp {^[0-9]{6}$} $code]} {return -1}
    set now [expr {[clock seconds] / 30}]
    foreach step [list $now [expr {$now - 1}] [expr {$now + 1}]] {
        if {$step > $last && [::tink::constant_time_equal $code [::tmfa::get_hotp $secret $step 6 SHA1]]} {return $step}
    }
    return -1
}
