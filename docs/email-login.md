# Email-code sign-in

Version 0.6.1 adds optional sign-in with a six-digit code. Enable
`email_login_enabled true` in the mount's `-config`. With `require_email_delivery`, `email_enabled`
and `aws_email_enabled` must also be true. Configure SES or an SQS queue and its worker. Queued sign-in codes expire with the challenge.

Password registration has a separate mount option, `login_after_email_verification`
(default `false`). When both flags are true, confirming the registration code
signs the user in and resumes their requested page after any required MFA.

Run `::web::user::initdb $connection $policy` before serving the new version. Its additive
migration adds `web_user_users.last_email_login_at`, defaulting to zero for
existing users. No new keys or private configuration values are required.

The login page offers a link to `$prefix/email-login`. A CSRF-protected POST
requests a code; `$prefix/email-login/verify` accepts it. Both routes allow GET
to display their forms. Existing `return_to` validation and “Stay signed in”
behavior apply. All existing active accounts can use a code, including accounts
whose email has not been verified (since 0.6.2). A successful code check marks
the email as verified. Since 0.7.0, new addresses also receive a code. Successful verification creates
a verified, passwordless account and signs the visitor in. First and last names
remain empty until the user adds them through Profile; public displays use
“Member” in the meantime. Requesting a code creates no account. Inactive accounts
receive the same public response but no code and cannot be reactivated this way.

The pending address is encrypted in the expiring browser challenge. Existing
accounts created in another browser are reused with their credentials and MFA
intact. Unconfirmed registrations never supply a password or profile for the
new account. A completed email sign-in provides five minutes of identity proof
for passwordless account changes, setting a password, and linking Google.

Codes are generated with the package's secure random generator and stored only
as keyed verifiers in expiring, browser-bound SQL sessions. Successful use
atomically consumes the challenge and rotates the session. Wrong attempts
remain counted after transaction rollback and across rate-limit windows.
`challenge_limit` bounds guesses, `code_ttl` controls expiry, `resend_cooldown`
limits mail requests, and the existing account/IP and registration CAPTCHA
policies apply. A code from password recovery cannot sign a user in.

MFA enrollment requires verified email. Users who enabled MFA must complete it
before they are authenticated. Only a completed sign-in updates
`last_email_login_at`. “Manage users” displays password
availability, providers linked in the tenant's identity table, and “Used email
code” with the last successful timestamp. It never displays codes, identity
verifiers, password hashes or provider tokens.

Set `show_verification_codes=true` for a development code and `aws_email_enabled=false` to disable SES/SQS. PROD
never displays the code. A failed delivery keeps the generic response; the user
can request another code after the cooldown.
