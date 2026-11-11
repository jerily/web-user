# SES is opt-in and runs after the account transaction commits. Credentials
# come from the AWS provider chain, never from account/site form fields.
proc ::web::user::validate_email_config {config} {
    set settings [dict get $config -config]
    if {![string is boolean -strict [dict get $settings email_enabled]]} {error "email_enabled must be a boolean"}
    if {![dict get $settings email_enabled] || [dict get $config -deliver] ne {} ||
        [dict get $config -store -env] ne "PROD"} {return}
    if {[dict get $settings email_from] eq {}} {error "email_from is required when PROD email is enabled"}
    email [dict get $settings email_from]
    if {![regexp {^[a-z][a-z0-9-]+-[0-9]+$} [dict get $settings email_region]]} {
        error "email_region must be an AWS region when PROD email is enabled"
    }
    package require awsses 1.0.16
}

proc ::web::user::notification {store user purpose} {
    list $purpose [unseal $store [dict get $user email] [list email [dict get $user id]]] {}
}

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
    if {$purpose in {verify reset}} {
        append text "\n\nThis code expires in [property [dict get $config -store] code_ttl] seconds. Never share it."
    } else {
        append text "\n\nIf you did not make this change, recover your account at $account/forgot and contact the site administrator."
    }
    return [dict create from [dict get $settings email_from] to [list $destination] subject $subject text $text]
}

proc ::web::user::deliver {config purpose destination code} {
    if {![dict get $config -config email_enabled]} {return}
    if {[dict get $config -deliver] ne {}} {
        {*}[dict get $config -deliver] $purpose $destination $code
        return
    }
    if {[dict get $config -store -env] ne "PROD"} {return}
    set message [email_message $config $purpose $destination $code]
    set client [::aws::ses::create [dict create region [dict get $config -config email_region]]]
    try {$client send_email $message} finally {$client destroy}
}

proc ::web::user::deliver_after_commit {config delivery} {
    if {$delivery eq {}} {return}
    if {[catch {deliver $config {*}$delivery}]} {
        # Keep the committed result and its replacement cookie usable. Do not
        # reveal whether a recovery address exists, or log addresses/codes/errors.
        puts stderr {web-user: account email delivery failed after commit}
    }
}
