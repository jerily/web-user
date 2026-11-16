# 
# Copyright Jerily LTD. All Rights Reserved.
# SPDX-FileCopyrightText: 2026 Neofytos Dimitriou (neo@jerily.cy)
# SPDX-License-Identifier: MIT.
# 

# Email is opt-in and runs after the account transaction commits. Credentials
# come from the AWS provider chain, never from account/site form fields.
proc ::web::user::validate_email_config {config} {
    set settings [dict get $config -config]
    if {![string is boolean -strict [dict get $settings email_enabled]]} {error "email_enabled must be a boolean"}
    if {[dict exists $settings email_queue_enabled] &&
        ![string is boolean -strict [dict get $settings email_queue_enabled]]} {
        error "email_queue_enabled must be a boolean"
    }
    set store [dict get $config -store]
    if {[dict get $store -env] eq "PROD" && [property $store email_verification_required] &&
        (![dict get $settings email_enabled] || ![property $store verification_emails_enabled])} {
        error "Required email verification needs email_enabled and verification_emails_enabled in PROD"
    }
    if {![dict get $settings email_enabled] || [dict get $config -deliver] ne {} ||
        [dict get $config -store -env] ne "PROD"} {return}
    if {[dict get $settings email_from] eq {}} {error "email_from is required when PROD email is enabled"}
    email [dict get $settings email_from]
    if {![regexp {^[a-z][a-z0-9-]+-[0-9]+$} [dict get $settings email_region]]} {
        error "email_region must be an AWS region when PROD email is enabled"
    }
    if {[dict exists $settings email_queue_enabled] && [dict get $settings email_queue_enabled]} {
        if {![dict exists $settings email_queue_url] ||
            ![regexp {^https://[A-Za-z0-9.-]+/[0-9]{12}/[A-Za-z0-9_-]{1,80}$} [dict get $settings email_queue_url]]} {
            error "email_queue_url must be the HTTPS URL of a standard SQS queue, not its name or ARN"
        }
        package require pure-tcl-aws-sqs 0.1.0
    } else {
        package require pure-tcl-aws-ses 0.1.0
    }
}

# Build a credential-free account security notification.
proc ::web::user::notification {store user purpose} {
    list $purpose [unseal $store [dict get $user email] [list email [dict get $user id]]] {}
}

# Format the selected account email and its expiry instructions.
proc ::web::user::email_message {config purpose destination code} {
    set settings [dict get $config -config]
    set site [dict get $settings title]
    set account [dict get $settings origin][dict get $config -prefix]
    switch -- $purpose {
        verify {
            set subject "Confirm your email for $site"
            set text "Your email confirmation code is: $code\n\nEnter it in the browser where you registered at $account/verify."
        }
        reset {
            set subject "Reset your password for $site"
            set text "Your password reset code is: $code\n\nEnter it in the browser where you requested recovery at $account/reset. If you did not request this, ignore this email."
        }
        password-changed {
            set subject "Your $site password was changed"
            set text "Your account password was changed. Existing sessions and recovery challenges were revoked. Your authenticator settings were preserved."
        }
        mfa-enabled {
            set subject "Two-factor authentication enabled for $site"
            set text "An authenticator was enabled for your account. Other sessions were signed out."
        }
        mfa-disabled {
            set subject "Two-factor authentication disabled for $site"
            set text "Your account authenticator was disabled. Other sessions were signed out."
        }
        default {error "unknown account email purpose"}
    }
    if {[dict exists $settings issuer] && [dict get $settings issuer] ne {}} {
        set subject "[dict get $settings issuer]: $subject"
    }
    if {$purpose in {verify reset}} {
        append text "\n\nThis code expires in [property [dict get $config -store] code_ttl] seconds. Never share it."
    } else {
        append text "\n\nIf you did not make this change, recover your account at $account/forgot and contact the site administrator."
    }
    return [dict create from [dict get $settings email_from] to [list $destination] subject $subject text $text]
}

# Send enabled account messages using the host transport, SQS, or SES.
proc ::web::user::deliver {config purpose destination code} {
    if {![dict get $config -config email_enabled]} {return}
    if {$purpose eq "verify" && ![property [dict get $config -store] verification_emails_enabled]} {return}
    if {[dict get $config -deliver] ne {}} {
        {*}[dict get $config -deliver] $purpose $destination $code
        return
    }
    if {[dict get $config -store -env] ne "PROD"} {return}
    set message [email_message $config $purpose $destination $code]
    set settings [dict get $config -config]
    if {[dict exists $settings email_queue_enabled] && [dict get $settings email_queue_enabled]} {
        set fields {}
        foreach key {from subject text} {dict set fields $key [list S [dict get $message $key]]}
        dict set fields to [list L [lmap address [dict get $message to] {list S $address}]]
        set expires 0
        if {$purpose in {verify reset}} {
            set expires [expr {[clock seconds] + [property [dict get $config -store] code_ttl]}]
        }
        set body [::tjson::typed_to_json [list M [dict create version {N 1} \
            expires_at [list N $expires] message [list M $fields]]]]
        set client [::aws::sqs::create [dict create region [dict get $settings email_region]]]
        try {
            set queue [dict get $settings email_queue_url]
            $client send_message $queue $body
        } finally {$client destroy}
        # The command prefix runs only after SQS accepts the message. It receives
        # the queue URL, never the address or code; failures leave the mail queued.
        if {[dict exists $settings email_queue_callback] && [dict get $settings email_queue_callback] ne {}} {
            {*}[dict get $settings email_queue_callback] $queue
        }
        return
    }
    set client [::aws::ses::create [dict create region [dict get $config -config email_region]]]
    try {$client send_email $message} finally {$client destroy}
}

# Attempt delivery without rolling back committed account changes.
proc ::web::user::deliver_after_commit {config delivery} {
    if {$delivery eq {}} {return}
    if {[catch {deliver $config {*}$delivery}]} {
        # Keep the committed result and its replacement cookie usable. Do not
        # reveal whether a recovery address exists, or log addresses/codes/errors.
        puts stderr {web-user: account email delivery failed after commit}
    }
}
