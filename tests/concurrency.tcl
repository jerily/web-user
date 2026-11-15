#
# Copyright Jerily LTD. All Rights Reserved.
# SPDX-FileCopyrightText: 2026 Neofytos Dimitriou (neo@jerily.cy)
# SPDX-License-Identifier: MIT.
#
# Run explicitly with WEB_USER_TEST_PG set to an isolated PostgreSQL connection.
if {[lindex $argv 0] eq "child"} {
    lassign $argv ignored directory number
    set f [open [file join $directory fixture] r]
    try {set fixture [read $f]} finally {close $f}
    set auto_path [dict get $fixture auto_path]
}
package require web-user
set ::env(ENV) PROD

# Open an independent worker connection and register its own crypto handles.
proc race_store {fixture} {
    set connection [::tpersist::db_connect -dialect postgresql -autobegin false {*}$::env(WEB_USER_TEST_PG)]
    set aead [::tink::register_keyset [dict get $fixture aead]]
    set mac [::tink::register_keyset [dict get $fixture mac]]
    set store [::web::user::create -connection $connection -config [dict create tenant [dict get $fixture tenant] \
        aead $aead mac $mac email_hash_salt race-test bcrypt_cost 4 login_captcha_after 0 collect_username true]]
    return $store
}
# Release resources owned by this worker after every scenario.
proc race_close {store} {
    ::tpersist::db_disconnect [dict get $store -connection]
    foreach key {-aead -mac} {::tink::unregister_keyset [dict get $store $key]}
}

if {[lindex $argv 0] eq "child"} {
    set store [race_store $fixture]
    rename ::web::user::insert_account ::web::user::race_insert_account
    # Hold both confirmations immediately before their competing SQL inserts.
    proc ::web::user::insert_account {store values} {
        close [open [file join $::directory ready-$::number] w]
        set deadline [expr {[clock milliseconds]+15000}]
        while {![file exists [file join $::directory go]]} {
            if {[clock milliseconds] > $deadline} {error "confirmation barrier timed out"}
            after 10
        }
        race_insert_account $store $values
    }
    set row [::web::user::session $store [dict get $fixture token$number]]
    set status 200
    if {[catch {
        ::tpersist::db_transaction [dict get $store -connection] {
            ::web::user::action_verify [dict create -store $store] $row {code 000123}
        }
    } message options]} {
        if {[lrange [dict get $options -errorcode] 0 1] ne {WEB USER}} {return -options $options $message}
        set status [lindex [dict get $options -errorcode] 2]
    }
    race_close $store
    puts $status
    exit
}
if {![info exists ::env(WEB_USER_TEST_PG)]} {error "Set WEB_USER_TEST_PG to an isolated PostgreSQL test database"}
foreach scenario {email username} {
    set f [file tempfile directory]
    close $f
    file delete $directory
    file mkdir $directory
    file attributes $directory -permissions 0700
    set fixture [dict create tenant race-[clock microseconds] auto_path $auto_path \
        aead [::tink::aead::create_keyset AES256_GCM] mac [::tink::mac::create_keyset HMAC_SHA256]]
    set store [race_store $fixture]
    set children {}
    try {
        ::web::user::initdb [dict get $store -connection]
        set password [::web::user::password_hash {a shared test password} {bcrypt_cost 4}]
        foreach number {1 2} {
            set id user_[::ksuid::generate_ksuid]
            set address [expr {$scenario eq "email" ? "same@example.com" : "user$number@example.com"}]
            set username [expr {$scenario eq "username" ? "shared" : "user$number"}]
            ::web::user::insert $store web_user_registrations [dict create id $id email_key [::web::user::email_key $store $address] \
                email [::web::user::seal $store $address [list email $id]] \
                password [::web::user::seal $store $password [list password-hash $id]] username $username \
                first_name {} last_name {} display_name {} created_at [clock seconds] expires [expr {[clock seconds]+900}]]
            dict set fixture token$number [::web::user::new_session $store verify $id 000123]
        }
        set f [open [file join $directory fixture] w]
        puts -nonewline $f $fixture
        close $f
        foreach number {1 2} {
            lappend children [open [list | [info nameofexecutable] [file normalize [info script]] child $directory $number] r]
        }
        set deadline [expr {[clock milliseconds]+15000}]
        while {![file exists [file join $directory ready-1]] || ![file exists [file join $directory ready-2]]} {
            if {[clock milliseconds] > $deadline} {error "workers did not reach the confirmation barrier"}
            after 10
        }
        close [open [file join $directory go] w]
        set statuses [lmap channel $children {string trim [read $channel]}]
        foreach channel $children {close $channel}
        set children {}
        if {[lsort $statuses] ne {200 409}} {error "unexpected concurrent $scenario results: $statuses"}
        if {[llength [::web::user::rows $store web_user_users]] != 1} {error "concurrent confirmations created multiple accounts"}
        if {$scenario eq "username"} {
            set number [expr {[lindex $statuses 0] == 409 ? 1 : 2}]
            set row [::web::user::session $store [dict get $fixture token$number]]
            ::tpersist::db_transaction [dict get $store -connection] {
                ::web::user::action_verify [dict create -store $store] $row {code 000123 username replacement}
            }
            if {[llength [::web::user::rows $store web_user_users]] != 2} {error "username correction did not activate the remaining registration"}
        }
        puts "PASS simultaneous $scenario confirmation: one winner, one recoverable conflict"
    } finally {
        close [open [file join $directory go] w]
        foreach channel $children {catch {close $channel}}
        race_close $store
        file delete -force $directory
    }
}
