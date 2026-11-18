# web-user

Licensed under the [MIT License](LICENSE).

Email/password accounts and optional Google Login mounted on a `tpathexp` site router.
See [Google Login](docs/google-login.md) for private configuration, explicit linking
and passwordless account management. Uses `tpersist`/TDBC, `tink-tcl`, `tmfa`, `tqrcodegen`, `ksuid-tcl`,
`jinja2-tcl`, `tjson`, `bcrypt-tcl`, and `twebserver`. The package owns its routes, templates, account records,
sessions and CSRF; the host owns configuration, connections, crypto keysets and
HTTP transport. See [MOUNTING.md](MOUNTING.md) for the complete mounting contract
and [docs/auth-review.md](docs/auth-review.md) for the authentication design.

```tcl
package require web-user 0.6.1
# Set ENV outside the application. Only exact LOCAL or PROD is accepted.
set connection [::web::user::connect [dict create \
    sqlite_path ./data/community.sqlite3 \
    postgresql [dict create -host db -database community -user community]]]
::web::user::initdb $connection ;# explicit maintenance; before workers start
set router [::tpathexp::router]
set accounts [::web::user::mount $router -connection $connection -policy {tenant example} \
    -secret_config [dict create aead_keyset $aeadKeyset mac_keyset $macKeyset email_hash_salt $emailHashSalt] \
    -config [dict create prefix /user origin https://community.example issuer Community \
        title Account master_template $siteMaster]]
```

`aeadKeyset` is Tink AES256_GCM keyset JSON; `macKeyset` is HMAC_SHA256
keyset JSON. Both belong in `-secret_config`, together with `email_hash_salt`. Store keyset JSON securely outside the database/repository and
reuse it across workers and restarts. The mount registers its own handles; call `::web::user::release $accounts` after
removing its routes and before closing the connection.
`emailHashSalt` is the required `email_hash_salt` config property. Generate it once
per site (for example, `openssl rand -hex 32`), keep it in private configuration,
and reuse it across workers and restarts. There is no default salt.
`connect` uses SQLite only for LOCAL and PostgreSQL only for PROD; no fallback.
The host must supply an autocommit connection (`-autobegin 0`) when using `create`
directly. A borrowed connection must match the environment; a mismatched dialect is rejected.
Sessions use `tsession-sqlite` in LOCAL and `tsession-postgres` in PROD. Schema changes never happen in `mount` or request handlers.

Requires Tcl 9.1 or newer. Dependency minimums include tpersist 0.1.2,
Jinja 0.1.1, tjson 1.0.28, tqrcodegen 1.1.1, ksuid 1.0.5 and twebserver 1.47.56.

Mount configuration accepts `assets_url` to supply the browser-asset base URL,
for example `https://cdn.example/cdn/user/_assets`.
Templates receive this value as `assets`; the default is the mount prefix plus
`/_assets`, and local asset routes remain available. The host is responsible for
uploading these files and allowing the CDN in its content security policy.

## Names and shared widgets

Set `collect_names true` in the account config to collect first and last names;
the default is false. Existing members can add names through `/user/profile`.
Names are encrypted at rest. `collect_display_name` enables an optional public
name; SQL NULL falls back to first name, then `Member`. `collect_username` enables
a unique lowercase public handle. Both default to false; email remains the login
identifier. See [WIDGETS.md](WIDGETS.md) for
the callback API and host wiring.

`email_verification_required` defaults to true. Set it false to activate new
accounts immediately while keeping email ownership unverified. The independent
`verification_emails_enabled` flag controls optional confirmation messages;
recovery and security notices retain their own delivery path. Required verification
in PROD needs both verification messages and the mount's `email_enabled` switch.

## Flows

The lifetimes, password and TOTP policy below are defaults. Configure them in
`create -config`; see [MOUNTING.md](MOUNTING.md).

- Register with email and a password of at least 15 characters (up to 72 UTF-8
  bytes), then enter the six-digit numeric email confirmation code before logging
  in. Email normalization trims and lowercases; passwords are preserved exactly.
  Pending registrations are independent and expire. The first successful
  confirmation creates the account and invalidates competing registrations for
  that email. A claimed username can be replaced on the verification form.
  Existing accounts cannot be overwritten by registration.
- Set `registration_captcha true` in `create -config` to show a CAPTCHA inside
  registration and forgotten-password forms, before any account changes or email.
  Login independently requires CAPTCHA before the third password check after two
  failures from the same IP by default (`login_captcha_after 3`,
  `login_captcha_window 900`). Set the threshold to 0 to disable login CAPTCHA.
  `captcha_length` sets the image length (4–12, default 6); `captcha_letters false`
  switches to digits only (default true includes letters).
  Counts use the existing SQL store. See [CAPTCHA configuration](MOUNTING.md#store-configuration).
- Login rotates the session. MFA-enabled accounts get only a pending challenge,
  never an authenticated principal, until the authenticator code succeeds.
  A rejected authenticator code redisplays the form with instructions to wait
  for the next code. The pending challenge, return destination, and attempt count
  are preserved.
- Forgot password produces a generic response. Reset requires the six-digit
  email code in the requesting browser, expires after 15 minutes, changes the
  password once, invalidates every session/reset challenge for that account, and
  preserves MFA.
- Change password at `/user/change-password` requires an authenticated session,
  the current password and matching new-password confirmation. It enforces the
  configured policy, preserves MFA, revokes every old session/challenge, and
  issues a fresh authenticated session for this browser.
- Close account at `/user/close-account` requires an authenticated session and
  the current password. Confirmation permanently deletes the account, profile
  and pending registrations for its email, revokes all sessions and challenges,
  and returns to sign-in. It does not delete content owned by host applications.
- Authenticator setup requires the current password. A pending, encrypted secret
  produces an `otpauth://` QR code and manual key. It becomes active only after
  confirmation. Disabling requires both the password and an unused current OTP.
  Enabling/disabling signs out other sessions. The enrollment code is consumed;
  wait for the next 30-second code before signing in again.
- Logout is POST with CSRF and deletes the server session. Auth sessions expire
  after 12 hours by default. Login's unchecked “Stay signed in” option instead
  keeps the authenticated session for 30 days (`persistent_session_ttl`) and
  issues a persistent cookie only after any required MFA succeeds. Anonymous/MFA
  challenges still expire after 10 minutes.

Account form errors render the relevant HTML form in the failed POST response,
with the error status and message. Safe fields such as email and profile names
are preserved; submitted passwords and codes are never filled back in. Expired
challenges return to their starting form, and rate limits show a reload link.
Successful sign-in still follows a validated `return_to` destination.

Email is opt-in: set mount properties `email_enabled true`, `email_from`, and
`email_region`. In PROD, `pure-tcl-aws-ses` 1.0.0+ sends verification
and recovery codes, MFA enabled/disabled notices, and password-change notices
for both changes and resets. It uses the AWS credential provider chain. LOCAL
never invokes SES. Disabled email sends nothing; PROD registration/recovery
therefore needs email enabled or an explicitly configured transport.

To queue mail instead, set mount properties `email_queue_enabled true` and
`email_queue_url` to the HTTPS URL of an existing standard SQS queue in
`email_region`, for example
`https://sqs.eu-central-1.amazonaws.com/123456789012/user-emails`.
Use the queue URL, not its name or ARN. This replaces `email_queue_name` and
avoids a queue URL lookup on every send. It requires `pure-tcl-aws-sqs` 1.0.0+. The optional
`email_queue_callback` command prefix receives the queue URL after SQS accepts
each message, allowing the host to wake its worker. Callback failures leave the
message queued; the host should schedule recovery independently. LOCAL never
contacts SQS. An explicit `deliver` transport still takes precedence.

Queue bodies are JSON objects with `version: 1`, `expires_at` (Unix seconds,
zero for security notices), and `message` (the SES `from`, `to` array, `subject`,
and `text` fields). The consumer should discard expired codes, pass `message`
to the SES client’s `send_email` method, and delete from SQS only after success. Messages include
recipient addresses and codes: restrict access and avoid logging their bodies.

The mount's `issuer` is the public site name used in authenticator apps and as
an email subject prefix. For example, `issuer ttrek.sh` with `title {Your account}`
produces `ttrek.sh: Confirm your email for Your account`. An empty issuer leaves
subjects unprefixed. The store's `tenant` identifies account data and is not
used for email branding.

An optional `deliver` command prefix replaces SES and receives `purpose email
code`; it also requires `email_enabled true` and may run in LOCAL. Purposes are
`verify`, `reset`, `password-changed`, `mfa-enabled`, and `mfa-disabled`. Notices
have an empty code and contain no password or MFA secret. Delivery happens after
commit. A failure logs a generic error while preserving the committed result
and replacement cookie; it does not expose account existence. Direct SES uses
the SDK's retry policy; queued delivery needs a host-provided consumer and retry
schedule. Operators must monitor delivery failures. Recovery codes must be entered
in the requesting browser and are never put in URLs or logs.

Only exact `ENV=LOCAL` displays current development codes in returned forms.
There is no request parameter or site property to enable code exposure in PROD.
The local display does not relax verification, expiry or replay rules. QR/manual
setup secrets necessarily appear during enrollment in both environments.

## Security and operations

User IDs are KSUIDs. Email confirmation and password-reset codes are six uniformly
random digits, including leading zeros. Session tokens use 32 random bytes. Both use
OpenSSL through `twebserver::random_bytes` and are stored only as Tink MAC digests
bound to tenant and purpose.
Email and first/last names are encrypted with Tink AEAD, bound to the tenant,
user and field. Registration, login and recovery look up the normalized email
using the unique `(tenant, email_key)` index. `email_key` is a Tink MAC over the
configured `email_hash_salt` and normalized address, also bound to tenant and
purpose. `::web::user::user_by_email $store $address` uses the same lookup and
returns the stored record (its email remains encrypted). MFA secrets
are AEAD-encrypted with tenant/user-associated data. Passwords use `bcrypt-tcl`
at cost 12 with random salts, then the complete bcrypt hash is encrypted with
Tink AEAD before storage in `web_user_users.password` or
`web_user_registrations.password`. The associated data binds it to the tenant,
account ID and `password-hash` purpose. Verification decrypts only the hash and
checks it with bcrypt; the original password is never stored. Inputs above 72 UTF-8
bytes or containing NUL characters are rejected rather than truncated. Native
MAC verification checks session, recovery, CSRF and TOTP codes; `tink-tcl` is
used without modifications.

Password verification requires this encrypted format. Bare bcrypt hashes are
rejected, with no migration or compatibility fallback. Existing accounts must use
email password recovery after upgrading; changing a password before upgrading
still writes the old format. Pending registrations from before the upgrade must
be restarted. Keep the AEAD keyset separate from the database and its backups,
and retain the original keyset when restoring encrypted account records.

All state-changing forms require session-bound CSRF. Cookies are host-only,
HttpOnly, SameSite=Lax and Path=/, and also Secure with a `__Host-` name in PROD.
Set the exact site `origin` (HTTPS in PROD); the host validates Host and handles
TLS. Context `addr` must come from the server or a trusted proxy adapter, never an
unvalidated request header. Limits use persistent 15-minute windows: 60 mutation
attempts per peer, 10 per action/account, 5 per challenge, 120 anonymous page
sessions per peer. Shared-proxy deployments should configure a trustworthy peer
identity and appropriate upstream limits.

TOTP allows the current step and one adjacent step each way, with a persisted
last-accepted counter to reject replay across sessions. Compare-and-set user
revisions and transactions prevent overlapping credential changes from silently
winning. Run `::web::user::prune $store` periodically to delete bounded batches of expired
sessions, temporary registrations and counting buckets after `cleanup_grace_period`
(default 3600 seconds) has elapsed. The grace period does not extend session or code
validity. The host owns scheduling.
Explicit `initdb` performs the recorded registration migration before workers start.

No OAuth, MFA backup-code system, roles, or account administration
is included. Hosts supply authorization policy: the example permits all verified
members to edit its shared wiki/blog, using those packages' existing callbacks.

## Development

Install the package and its native dependencies through ttrek:

```sh
ttrek install -y web-user
```

From a source checkout with native dependencies installed, add the checkout to
`TCLLIBPATH` or install the pure Tcl package with CMake:

```sh
cmake -S . -B build -DBUILD_TESTING=OFF -DCMAKE_INSTALL_PREFIX=/path/to/prefix
cmake --install build
```

The package uses unmodified `tink-tcl` 20240704.0.2, `bcrypt-tcl` 2.0.1,
`tmfa` 1.1.2, `tsession` 2.0.0, and `twebserver` for cryptographic random bytes.
Keep persistent keysets and databases outside the source and install directories.

Explicit `initdb` migrates the previous salted account schema to separate pending
registrations, preserving verified accounts and valid confirmation sessions.
Older unsalted email indexes remain incompatible and require a fresh database;
there is no unsalted lookup fallback. Changing `email_hash_salt` or the MAC key
invalidates email lookups. Preserve both with the encryption keysets.

With dependencies on `TCLLIBPATH`:

```sh
ENV=LOCAL tclsh tests/all.tcl
# Optional: also run PROD account/password/session cases against PostgreSQL:
WEB_USER_TEST_PG='-host 127.0.0.1 -port 55439 -database postgres -user test' \
  ENV=LOCAL tclsh tests/all.tcl
```

Tests exercise registration, recovery, session isolation/revocation, native crypto,
MFA/replay, persistent limits, configuration, and LOCAL/PROD output. PostgreSQL
runs use unique tenant namespaces; never point tests at a production database.

### Session cookies

`tsession` signs, reads and sets each mount's cookie using its own configuration
and the store's Tink MAC handle. Session records, absolute expiry and revocation
use `tsession-sqlite` (LOCAL) or `tsession-postgres` (PROD), with the same borrowed
`tpersist` connection as account writes. `initdb` creates `tsession_sessions`;
there is no old-table fallback or session migration. Existing sessions are
invalidated by this storage change. Run explicit initialization before PROD startup. Cookies
are HttpOnly, SameSite=Lax, Path=/, and Secure with a `__Host-` name in PROD.

Request schemas use `topenapi` 0.2.0; see `schemas/operations.json` and the mounting guide.

## Database indexes

Session and account reads use primary/unique indexes. Expired rate-limit cleanup uses `web_user_limits_expiry (tenant, expires)`.

All database operations use `tpersist`. Rerun the explicit `initdb` maintenance
operation to add these indexes to existing databases. Index creation is
idempotent and never runs in request handlers. The example-community integration
suite verifies the access paths with SQLite and PostgreSQL EXPLAIN plans.

## Groups and permissions

Use `sync_access` to apply configured group membership and permission grants,
then `has_permission` to authorize actions for a verified account. See
[Groups and permissions](docs/access.md) for INI examples, startup/maintenance
integration, and revocation behavior.

## User administration

Accounts with `users.manage` get an **Account → Manage users** link. The directory
lists registration, last sign-in and last visit dates, authenticator status and
configured groups. Sort by recent sign-in, recent activity or newest registration,
with tenant-scoped pagination. See [user administration](docs/admin.md) for setup and
the display contract.

Account identities use `user_<ksuid>` across registration, account and profile
records. See [user ID migration](docs/user-ids.md) for the explicit maintenance
step that updates existing identities and their encrypted data and sessions.
