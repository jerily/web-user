# Email-code sign-in

Version 0.6.1 adds optional sign-in with a six-digit code. Enable
`email_login_enabled true` in the mount's `-config`. In PROD, `email_enabled`
must also be true and the existing delivery callback, SES or SQS settings must
be configured. The delivery callback receives purpose `login`, the destination
and the code. Queue messages expire with the code.

Run `::web::user::initdb $connection` before serving the new version. Its additive
migration adds `web_user_users.last_email_login_at`, defaulting to zero for
existing users. No new keys or private configuration values are required.

The login page offers a link to `$prefix/email-login`. A CSRF-protected POST
requests a code; `$prefix/email-login/verify` accepts it. Both routes allow GET
to display their forms. Existing `return_to` validation and “Stay signed in”
behavior apply. Unknown, inactive and unverified email addresses receive the
same public response as eligible users. This flow does not create accounts.

Codes are generated with the package's secure random generator and stored only
as keyed verifiers in expiring, browser-bound SQL sessions. Successful use
atomically consumes the challenge and rotates the session. Wrong attempts
remain counted after transaction rollback and across rate-limit windows.
`challenge_limit` bounds guesses, `code_ttl` controls expiry, `resend_cooldown`
limits mail requests, and the existing account/IP and registration CAPTCHA
policies apply. A code from password recovery cannot sign a user in.

Configured MFA must complete before the user is authenticated. Only a completed
sign-in updates `last_email_login_at`. “Manage users” displays password
availability, providers linked in the tenant's identity table, and “Used email
code” with the last successful timestamp. It never displays codes, identity
verifiers, password hashes or provider tokens.

LOCAL displays a development code for testing and does not call SES/SQS. PROD
never displays the code. A failed delivery keeps the generic response; the user
can request another code after the cooldown.
