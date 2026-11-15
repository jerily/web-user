# Mounting web-user onto a site

A site creates a `tpathexp::router` in each worker and passes it to package `mount`
procedures. A mount registers route handlers with a prefix and captures its own
store/configuration in Tcl command prefixes. There is no global active site.
Different routers, tenants and mounts can use different layouts and databases.

The lifecycle is:

1. The host loads packages and validates site properties.
2. An explicit initializer opens a connection and runs package `initdb` procedures.
   Content packages may also import/synchronize their source directories here.
3. Each worker opens its own connection, registers crypto keys, and creates stores.
4. The host mounts packages before any catch-all route, then registers host routes.
5. The HTTP adapter maps `httpMethod` to `method`, preserving body, headers,
   path, `isBase64Encoded` and trusted context. It calls `$router dispatch $request
   $context`, then sends the returned response dictionary.
6. On shutdown the host closes its connection and unregisters crypto handles.

Handlers receive `request context params` and return `statusCode headers body`.
`tpathexp` handles path/method matching, 404/405 and HEAD body suppression.
Handlers are independent of the listening server and can be adapted to Lambda.

Expected account errors return HTML with the original error status (for example,
400 for invalid form fields and 401 for incorrect credentials). They render the
relevant form directly, preserve non-secret fields and `return_to`, and keep CSRF
and attempt limits enforced. Expired challenges restart at registration, recovery,
or login as appropriate. Custom form templates can use the `reload_form` boolean
to show a reload link and disable submission when a fresh form is required.

## Connection and key ownership

Set `ENV` to exactly `LOCAL` or `PROD` before loading the host configuration.
`web-user::connect` selects SQLite in LOCAL and PostgreSQL in PROD. Initialize
schema explicitly before workers serve requests:

```tcl
package require web-user 0.4.0
set connection [::web::user::connect [dict create \
    sqlite_path ./data/accounts.sqlite3 \
    postgresql [dict create -host db -database accounts -user accounts]]]
::web::user::initdb $connection
set accountStore [::web::user::create -connection $connection -config [dict create tenant mysite \
    aead $aeadHandle mac $macHandle email_hash_salt $emailHashSalt]]
set router [::tpathexp::router]
```

The two handles are registered Tink keysets owned by this worker: AES256_GCM
for AEAD and HMAC_SHA256 for MAC. Provision keyset JSON once, keep it outside
source control with restricted permissions, and reuse it across restarts.
Keep keysets separate from SQL backups. The AEAD key encrypts the bcrypt hash
in both permanent accounts and pending registrations, bound to the tenant,
account ID and password purpose. Bare hashes are not accepted: accounts created
before this storage change need email password recovery after upgrading, and
old pending registrations should be restarted. There is no password migration.
Unregister the handles after destroying the worker's router, then disconnect
its database. A directly supplied connection must use `-autobegin 0`.

## Mounting accounts and content

```tcl
set site [dict create master_template $master origin https://community.example]
set accounts [::web::user::mount $router -store $accountStore -config [dict create prefix /user origin [dict get $site origin] issuer Community \
        master_template [dict get $site master_template]]]
::web::forum::mount $router -store $accountStore -user $accounts -prefix /forum \
    -config [dict create master_template [dict get $site master_template]]
foreach kind {wiki blog} {
    ::web::${kind}::mount $router -store [dict get $contentStores $kind] \
        -prefix /$kind -authorize [list ::web::user::authorize_permission $accounts $kind.edit] \
        -csrf [list ::web::user::csrf $accounts] \
        -context [list ::site_properties $accounts] \
        -config [dict create allow_create true \
            master_template [dict get $site master_template]]
}
```

The content packages' generic `-context` callback receives `request context`
and returns typed Jinja properties. For example:

```tcl
proc site_properties {accounts request context} {
    set user [::web::user::current_user $accounts $request $context]
    dict create signed_in [list BOOL [expr {$user ne {}}]]
}
```

Values are evaluated once per request and override the template context for that
request only. Hosts may provide any trusted typed properties, not just editing
visibility. Wiki/blog links are generated only when their authorization callback
allows the corresponding action. `show_edit_controls false` can hide them
further; it cannot grant access. `-authorize` and `-csrf` protect editor routes.

Grant `wiki.edit` for creating/editing wiki pages and `blog.edit` for
creating/editing blog posts through [groups and permissions](docs/access.md).
The two grants are independent, and `forum.moderate` implies neither.

The content store uses
`-domain`; use the same site identity as the account store's `-tenant` to keep
content partitioning aligned. Site-to-tenant mapping is trusted configuration,
never a request parameter. Use separate keys/tenants for unrelated sites.

`web-user::mount` accepts `-store` and `-config`. Put `prefix` (default `/user`,
non-root) and `deliver` in `-config`. Its returned mount dictionary
is passed to `current_user`, `authorize`, and `csrf`. It validates settings,
templates, origin and route collisions before registration. Prefixes must not
overlap other packages or prior catch-all routes.

Configuration properties are `master_template` (template source), `templates`
(named template dictionary), `title`, `issuer`, required `origin`, `prefix`, `deliver`, and typed template
`properties`. Reserved account fields override host template properties. The master
replaces `page.html.jinja` for this mount. Templates use `{% block body %}`; ordinary
values are escaped. The QR SVG is generated by `tqrcodegen`, the only raw markup
in the account template. Do not pass user-supplied template source. Overrides are
per mount and do not modify package defaults. The example loads site and per-package properties through tconfig INI sections.

## Store configuration

Pass a trusted dictionary to `create -connection $connection -config $account`.
Required fields are `tenant`, `aead`, `mac` (registered key handles owned by
the worker), and `email_hash_salt`. All store properties belong in `-config`.
All policy values are validated and captured in the store:

| Property | Default | Meaning |
| --- | --- | --- |
| `email_hash_salt` | Required | Persistent site-specific salt included in the keyed email lookup digest. Blank values are rejected by `create`. |
| `bcrypt_cost`, `password_min_length` | 12, 15 | New hashes and minimum characters; bcrypt's 72-byte cap always applies. |
| `collect_names` | false | Require first/last names at registration and enable the authenticated profile-edit form. |
| `collect_display_name` | false | Show an optional, editable public name. Blank names remain SQL NULL and fall back to first name, then Member. |
| `collect_username` | false | Require a public handle at registration/profile editing; 3–32 ASCII letters, digits, underscores, starting with a letter. Stored lowercase and unique per tenant for permanent accounts. Email remains the login identifier. |
| `email_verification_required` | true | Keep new registrations temporary until confirmation. False activates immediately with email still unverified. Existing active accounts are unaffected by changes. |
| `verification_emails_enabled` | true | Allow verification messages independently of recovery and security notifications; the mount's email_enabled switch also applies. |
| `resend_cooldown` | 60 | Fixed per-email resend window in seconds (1–3600), in addition to shared verification attempt limits. |
| `registration_captcha` | false | Show and require an image CAPTCHA inside the registration and forgotten-password forms. |
| `captcha_ttl` | 300 | Image challenge lifetime in seconds (1–3600), capped by the browser session’s remaining lifetime. |
| `captcha_length` | 6 | Number of characters in each image (4–12). Applies to registration, recovery, and login. |
| `captcha_letters` | true | Include uppercase letters and digits, excluding ambiguous characters. Set false for digits only (0–9). Answers are case-insensitive. |
| `login_captcha_after` | 3 | Require a CAPTCHA before this password-check attempt from the same IP; 3 means after two failures, 1 means always, 0 disables it. |
| `login_captcha_window` | 900 | Fixed counting window in seconds (1–86400) for failed login password checks. |
| `totp_digits`, `totp_period`, `totp_algorithm` | 6, 30, SHA1 | Shared by key URI, verification and LOCAL display. |
| `totp_window` | 1 | Adjacent accepted steps on either side; replay protection always applies. |
| `session_ttl`, `code_ttl`, `challenge_ttl` | 43200, 900, 600 | Authenticated, email-code and anonymous/MFA lifetimes in seconds. |
| `persistent_session_ttl` | 2592000 | Authenticated lifetime in seconds when “Stay signed in” is selected (30 days by default; 1–2592000 and at least `session_ttl`). |
| `cleanup_grace_period` | 3600 | Keep expired records for this many additional seconds before scheduled deletion (0–2592000). Does not extend validity. |
| `throttle_window` | 900 | Persistent rate-limit window in seconds. |
| `browse_limit`, `post_limit`, `account_limit`, `challenge_limit` | 120, 60, 10, 5 | Maximum attempts in that window. |
| `form_max_bytes` | 32768 | Maximum encoded form size. |

`password_min_length` accepts 6–72 characters; web-user defaults to 15.
The host chooses its policy through the account config dictionary.

Set `registration_captcha true` in the store's account configuration to
show an image directly in both the registration and forgotten-password
forms. There is no separate CAPTCHA step or route. The answer is checked before
hashing a registration password, creating/updating an account, or sending mail.
For tconfig hosts, these are `[account]` properties:

```ini
registration_captcha = true
login_captcha_after = 3
login_captcha_window = 900
captcha_ttl = 300
captcha_length = 6
captcha_letters = true
```

Images default to six characters. Set `captcha_letters = false` for digits only,
and `captcha_length` to a value from 4 through 12 to change their length. Image
width and form instructions adjust automatically. Short numeric challenges have
fewer possible answers; keep the existing attempt limits enabled.

Login CAPTCHA is independent of `registration_captcha`. By default, two failed
password checks from the same trusted `context addr` cause the login form to
show a CAPTCHA for the third and subsequent attempts in that window. Missing,
incorrect or expired CAPTCHA answers are rejected before password checking,
even when a client skips the form and POSTs directly. GET requests, successful
logins, malformed forms, CSRF failures and CAPTCHA failures do not increase the
password-failure count. Unknown and inactive accounts use the same generic
login failure and count identically. An IP's count is not cleared by another
user's successful login from that IP.

Counts are scoped to tenant, mount and IP, survive worker restarts, and use the
existing SQL `web_user_limits` table. No tratelimit dependency, Valkey connection,
or new schema is needed. A login form/password check adds one indexed count
lookup; failed password checks update the count outside the account transaction.
Other forms do not query it. Windows are fixed buckets aligned to the Unix epoch,
so a count resets at a window boundary; this is not a rolling window. Existing
per-account and peer hard limits still apply. Do not accept a client-supplied
`X-Forwarded-For` as `context addr`; the host must resolve trusted proxies.

`login_captcha_after 3` permits two typos before adding friction. A shared public
IP can accumulate failures from several users; hosts with that audience may
prefer 5. Set it to 0 to disable login CAPTCHA. The `tcaptcha` package is loaded
when either registration or login CAPTCHA is enabled.

Each image has a random ID and a server-side, expiring verifier bound to the
tenant, mount, form action, and browser session. The answer and credentials are
not stored in CAPTCHA state. The form sends the random `captcha_id` and the user's
`captcha_answer`. The server looks up the verifier and checks the answer with
Tink HMAC; the verifier stays on the server. Each submitted image is consumed before account
work in a separate transaction: a failed password check or later validation
failure cannot restore it. Wrong or expired answers redisplay the same form
with a new image; passwords and CAPTCHA answers are never reflected in HTML.
"Try another image" reloads the form. Images from other tabs remain usable once
until expiry, but verification attempt limits remain tied to the browser session
and action. Image issuance is also rate-limited by peer. Expired verifier rows
are removed by the existing session pruning operation.

Custom `form.html.jinja` overrides must render `captcha_png` and a hidden
`captcha_id`, and collect `captcha_answer`, whenever `captcha_png` is nonempty.
These fields accompany the form's usual fields and `csrf`. The default template
already handles registration, login, and forgotten-password forms. Templates also
receive `captcha_length` and the boolean `captcha_letters` for instructions and
input constraints.

The image CAPTCHA has no audio alternative; hosts enabling it should offer an
accessible registration/recovery alternative. It supplements the existing rate
limits. See [OWASP's guidance on introducing CAPTCHA after failed logins](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#captcha).

Generate the salt once with `openssl rand -hex 32`, store it in private host
configuration, and reuse it across workers and restarts. In tconfig INI, set
`[account] email_hash_salt`; encrypted deployments can use `enc:email_hash_salt`.
The salt is included in the Tink MAC input along with the normalized email;
tenant and purpose are also bound. Email and names remain AEAD-encrypted.
There is no unsalted lookup fallback. The registration migration preserves existing salted lookups; changing the salt or MAC key invalidates existing email lookups.

Use the same policy for all workers serving a tenant. Changing TOTP digits,
period or algorithm requires existing authenticators to be enrolled again;
the app stores the provisioning parameters. Issuer is validated directly at
mount time. Enrollment calls `tmfa::keyuri` with a generated per-user secret and
the actual email address. Recovery tokens and authenticator secrets always use
cryptographic randomness; there is no shared secret or development key in code.

## Account endpoints (relative to prefix)

| Path | Methods | Purpose |
| --- | --- | --- |
| bare prefix, `/` | GET/HEAD | Authenticated account page |
| `/profile` | GET/HEAD, POST | Edit enabled name/username fields when any profile collection flag is enabled |
| `/register` | GET/HEAD, POST | Registration form / begin email verification |
| `/verify` | GET/HEAD, POST | Confirm a registration or optional email verification; a username collision permits submitting a replacement with the same code |
| `/resend-verification` | POST | Replace this browser’s verification code without changing its pending credentials |
| `/login` | GET/HEAD, POST | Password form / authenticate or require MFA |
| `/forgot` | GET/HEAD, POST | Recovery form / issue reset code |
| `/change-password` | GET/HEAD, POST | Current password plus new password and confirmation; revoke old sessions, preserve MFA |
| `/close-account` | GET/HEAD, POST | Confirm current password, permanently delete account/profile and pending registrations, revoke all sessions |
| `/reset` | GET/HEAD, POST | Reset form / consume code and replace password |
| `/two-factor` | GET/HEAD, POST | Pending-login OTP challenge |
| `/two-factor/setup` | GET/HEAD, POST | Setup page; `operation=begin` or `confirm` |
| `/two-factor/disable` | GET/HEAD, POST | Disable using password and OTP |
| `/logout` | POST | Revoke browser session |

Each endpoint is registered individually in `mount` with its own handler.
Shared helpers enforce session, CSRF, rate-limit and transaction rules.

Form pages use `Referrer-Policy: same-origin` so browser submissions retain
an `Origin` header for comparison with the configured site origin. Null and
foreign origins remain rejected, as do invalid session-bound CSRF tokens.
In LOCAL mode, requests to `localhost`, `127.0.0.1`, or `[::1]` compare the
browser's Origin against the request's loopback host and port, using the scheme
from the configured origin. This supports either address and custom local ports
without disabling CSRF checks. PROD always uses the configured origin.

POST accepts URL-encoded forms and a `csrf` field. Required fields: registration
and login `email password`; forgot `email`; verify/MFA `code`; reset `code password`;
change password `current_password password confirm_password`; close account `current_password`;
setup begin `operation password`; setup confirm `operation code`; disable
`password code`. Duplicate keys, invalid encodings, oversized forms, wrong content
types and invalid CSRF are rejected. GET creates an anonymous session if needed.
Login additionally accepts optional `stay_signed_in=1`; omission means false.
Only the login endpoint accepts this field. The built-in checkbox starts unchecked
and preserves an explicit choice when the login form is redisplayed.
Successful account POSTs render the next form directly so LOCAL codes can be
shown once without persisting plaintext; reloading a consumed POST is rejected.

Unauthenticated GET/HEAD requests to protected account pages receive a 302 to
`/user/login?return_to=...` (using the configured prefix). The original path and
query are retained. Login, registration, verification, recovery and MFA forms
carry this destination through their actions and links. After successful login
and any required MFA, a 302 returns the browser there with its new session cookie.
Registration still requires sign-in after email verification; it does not bypass
that policy. Without a return destination, the usual account page is rendered.
Only local paths beginning with a single slash are accepted; external URLs,
backslashes, control characters and encoded authorities are ignored.

Hosts can return `::web::user::sign_in_redirect $accounts $request` when another
page requires login. Do not redirect invalid-password or forbidden-action errors
as though they were anonymous page visits.

`current_user mount request ?context?` returns an empty dictionary or the signed-in
member's `id email first_name last_name display_name username email_verified
mfa_enabled` fields. Pending verification/recovery/MFA sessions return empty.
`authorize_permission mount permission request context action path` checks the
signed-in account's current grant for the exact permission. Bind `wiki.edit` or
`blog.edit` as shown above. Revocation applies to already-open forms on submission.
`authorize mount request context action path` only checks authentication; use the
permission adapter for content editing. `csrf mount issue request context {}` returns
a token, and `csrf mount verify request context submitted` returns a boolean.
The wiki/blog editing callback contract matches these signatures exactly.

Invalid or reused login authenticator codes return the MFA form with HTTP 401
and instructions to wait for the next code. The code input stays empty; the pending
session, return destination, and attempt count are preserved. Other form-specific
recovery responses include CAPTCHA failures and username confirmation conflicts.
Remaining expected request errors return plain text and HTTP status. Unexpected failures
propagate to the host, which should return a generic 500 without logging request
credentials or sensitive database parameters. See `example-community` for a
complete adapter, persistent LOCAL keys, shared master, and all four mounts.

## Email delivery and LOCAL codes

Set the mount's `issuer` to the public site name. All built-in email subjects
start with `issuer: ` when it is nonempty; for example, `issuer ttrek.sh` and
`title {Your account}` produce `ttrek.sh: Confirm your email for Your account`.
This is the same label used in authenticator apps. An empty issuer preserves
unprefixed subjects. The store's `tenant` remains the account-data identifier.

Mount settings `email_enabled` (false by default), `email_from` (sender address)
and `email_region` (AWS region) control SES delivery. With `email_enabled true`
in PROD, sender and region are required and `awsses` 1.0.16 is loaded. Credentials
come from the AWS SDK provider chain. Configure SES sender authorization in the
chosen region. LOCAL never invokes SES.

An optional `deliver` command prefix overrides SES, still gated by
`email_enabled`; it can run in LOCAL for custom transports/tests. Arguments are
`purpose email code`. Purposes: `verify`, `reset`, `password-changed`,
`mfa-enabled`, `mfa-disabled`. The last three carry an empty code. Password
changes and resets both notify the account owner; MFA enrollment notifies only
after successful confirmation. No password or authenticator secret is emailed.

Delivery follows commit. A transport failure logs a generic error, keeps the
completed state and replacement cookie, and does not disclose whether a recovery
address exists. There is no durable outbox or application retry worker. Monitor
failures; a user can repeat registration/recovery to request a fresh code.
When delivery is disabled, PROD has no code delivery path by default.

LOCAL shows verification, recovery and current authenticator codes in forms.
PROD suppresses these fields; expiry, replay and CSRF checks apply in both modes.
Reset codes must be entered in the browser that requested them. QR/manual setup
secrets appear during authenticator enrollment in both environments.

## Cookie ownership

Each account mount configures `tsession::cookie` with its own cookie name and
borrowed Tink MAC handle. `tsession` signs, verifies, reads and sets the cookie;
`tsession-sqlite` (LOCAL) and `tsession-postgres` (PROD) persist sessions in
`tsession_sessions`. Both borrow the account connection so credential changes
and revocation are atomic. `create` and `initdb` reject a mismatched dialect.
`web-user` owns session policy and rotation; stores enforce absolute expiry. PROD passes
`-secure true`, LOCAL passes `-secure false`. HttpOnly, SameSite=Lax and Path=/
apply in both environments; PROD also uses a `__Host-` cookie name. A host must
keep the keyset handle alive for the mount's lifetime. No global tsession store
or middleware initialization is used, so separate mounts cannot overwrite each
other's cookie configuration.

By default, sign-in uses a browser-session cookie with no `Max-Age`, while SQL
limits the session to `session_ttl`. Selecting “Stay signed in” uses
`persistent_session_ttl` and adds `Max-Age` for the remaining SQL lifetime. Cookie
refreshes cannot extend that absolute expiry. Browser session restoration can
retain ordinary session cookies; SQL expiry still applies.

For MFA accounts, the preference is stored in the pending challenge, which keeps
its short lifetime and browser-session cookie. Persistence starts only after a
valid authenticator code. Password changes and MFA enrollment/disable preserve
the preference on the replacement session; logout and password recovery clear it.
Existing sessions without the preference keep their original behavior. No schema
migration is needed because the preference lives in the session's stored data.

## Request validation

`schemas/operations.json` contains inline OpenAPI operations for each POST form.
Password schemas require at least one character. Registration, reset and password
change actions enforce the configured minimum and UTF-8 byte limit before saving.
Mounting captures the JSON and adjusts fields for the three profile collection flags. `topenapi`
0.2.0 validates required fields, types, lengths and allowed operations after
strict form decoding and CSRF verification. Unknown form fields are rejected.
Authorization, password checks, MFA replay and transactions remain in the handlers.
No credential-bearing validation diagnostics are returned to the browser.

## Shared profile widget

The host can bind `::web::user::widget $accounts profile` to another package's
`widgets profile` callback. See [WIDGETS.md](WIDGETS.md) for the generic contract,
forum wiring, template overrides and the additive profile-table upgrade.


## Registration policy and migration

`web_user_users.active` controls login eligibility; `verified` records email
ownership. Required verification saves the password hash and encrypted names/email
in `web_user_registrations`, with an expiry matching `code_ttl`. Each registration
has an independent ID and session-bound HMAC code verifier in `tsession_sessions`.
Multiple registrations for an email or username may coexist. A fresh request
never replaces another pending password or profile.

Confirmation creates the permanent account/profile and revokes competing pending
registrations for that email in one transaction. Unique indexes on permanent
`(tenant, email_key)` and `(tenant, username)` settle races between workers. If
another email has claimed the username, the form returns 409 and lets the user
choose another username with the same unexpired code. A failed promotion leaves
its registration and code usable. Pending email/expiry and expiry-only indexes
support scoped lookup and cleanup; username is nullable when not collected.

Optional verification activates immediately, but leaves `verified = 0`. When
verification messages are enabled, the user may confirm or proceed to login;
a signed-in user can request another code from the account page. MFA enrollment
requires verified email. Password recovery works for active unverified accounts;
a successful reset proves email ownership and sets verified while revoking old
sessions. Existing MFA is preserved.

In PROD, required verification rejects configurations with either
`verification_emails_enabled false` or mount `email_enabled false`; there is no
built-in alternate verifier. LOCAL can display development codes without sending
mail. Disabling verification messages never disables reset emails or password/MFA
notifications. Mail remains an after-commit attempt, without a durable outbox;
resend provides recovery from a delivery failure. Verification limits are shared
per email as well as per challenge, and resending cannot reset those counters.

Run `::web::user::initdb $connection` during explicit maintenance before starting
workers. Its transactional, recorded migration moves legacy unverified users and
their encrypted profiles into temporary registrations, preserving their existing
valid verification sessions and deadlines. Verified legacy users become active.
Repeated initialization preserves newly active unverified accounts. The session
schema is unchanged. Back up the database before upgrading an existing deployment.

## Scheduled cleanup

The host schedules maintenance, for example every five minutes, using its own
connection and tenant store. Each procedure accepts an optional batch size (default
500, range 1–10000):

```tcl
::web::user::prune_sessions $store 500
::web::user::prune_registrations $store 500
::web::user::prune_limits $store 500
set counts [::web::user::prune $store 500]
# registrations N sessions N limits N
```

The individual procedures return deleted-row counts. The wrapper reports counts
per category. A record becomes eligible when `expires <= now - cleanup_grace_period`;
the default grace period keeps expired data for one extra hour. Registration cleanup
also revokes associated verification sessions. Every deletion rechecks tenant and
the same cutoff so a renewed row is preserved; repeated runs are safe. A full batch
means another pass may be useful. Cleanup never removes active accounts. The grace
period delays physical deletion only: expired sessions and codes remain unusable.

For explicit concurrency validation, set `WEB_USER_TEST_PG` to a disposable
PostgreSQL connection-options list and run `tclsh9.1 tests/concurrency.tcl`. The
migration test uses a separate empty database selected by `WEB_USER_MIGRATION_PG`.
