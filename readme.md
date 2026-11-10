# web-user

Email/password accounts mounted on a `tpathexp` site router. OAuth is outside this
package. Uses `tpersist`/TDBC, `tink-tcl`, `tmfa`, `tqrcodegen`, `ksuid-tcl`,
`jinja2-tcl`, `tjson`, `bcrypt-tcl`, and `twebserver`. The package owns its routes, templates, account records,
sessions and CSRF; the host owns configuration, connections, crypto keysets and
HTTP transport. See [MOUNTING.md](MOUNTING.md) for the complete mounting contract
and [docs/auth-review.md](docs/auth-review.md) for the authentication design.

```tcl
package require web-user 0.1.6
# Set ENV outside the application. Only exact LOCAL or PROD is accepted.
set connection [::web::user::connect [dict create \
    sqlite_path ./data/community.sqlite3 \
    postgresql [dict create -host db -database community -user community]]]
::web::user::initdb $connection ;# explicit maintenance; before workers start
set store [::web::user::create -connection $connection -config [dict create tenant example \
    aead $aeadHandle mac $macHandle email_hash_salt $emailHashSalt]]
set router [::tpathexp::router]
set accounts [::web::user::mount $router -store $store -config [dict create prefix /user origin https://community.example issuer Community \
        title Account master_template $siteMaster]]
```

`aeadHandle` is a registered Tink AES256_GCM keyset; `macHandle` is a registered
HMAC_SHA256 keyset. Store keyset JSON securely outside the database/repository and
reuse it across workers and restarts. Each worker registers its own handles.
`emailHashSalt` is the required `email_hash_salt` config property. Generate it once
per site (for example, `openssl rand -hex 32`), keep it in private configuration,
and reuse it across workers and restarts. There is no default salt.
`connect` uses SQLite only for LOCAL and PostgreSQL only for PROD; no fallback.
The host must supply an autocommit connection (`-autobegin 0`) when using `create`
directly. A host borrowing a connection is responsible for selecting the same
backend policy. Schema changes never happen in `mount` or request handlers.

Requires Tcl 9.1 or newer. Dependency minimums include tpersist 0.1.1,
Jinja 0.1.1, tjson 1.0.27, tqrcodegen 1.1.1, ksuid 1.0.5 and twebserver 1.47.56.

## Names and shared widgets

Set `collect_names true` in the account config to collect first and last names;
the default is false. Existing members can add names through `/user/profile`.
Names are encrypted at rest. The reusable profile widget exposes the first name
as `display_name`, with `Member` as the fallback. See [WIDGETS.md](WIDGETS.md) for
the callback API and host wiring.

## Flows

The lifetimes, password and TOTP policy below are defaults. Configure them in
`create -config`; see [MOUNTING.md](MOUNTING.md).

- Register with email and a password of at least 15 characters (up to 72 UTF-8
  bytes), then enter the six-digit numeric email confirmation code before logging
  in. Email normalization trims and lowercases; passwords are preserved exactly.
  Register again to replace a lost/expired verification code and pending password.
  Verified accounts cannot be overwritten by registration.
- Login rotates the session. MFA-enabled accounts get only a pending challenge,
  never an authenticated principal, until the authenticator code succeeds.
- Forgot password produces a generic response. Reset requires the six-digit
  email code in the requesting browser, expires after 15 minutes, changes the
  password once, invalidates every session/reset challenge for that account, and
  preserves MFA.
- Authenticator setup requires the current password. A pending, encrypted secret
  produces an `otpauth://` QR code and manual key. It becomes active only after
  confirmation. Disabling requires both the password and an unused current OTP.
  Enabling/disabling signs out other sessions. The enrollment code is consumed;
  wait for the next 30-second code before signing in again.
- Logout is POST with CSRF and deletes the server session. Auth sessions expire
  after 12 hours; anonymous/MFA/setup sessions after 10 minutes.

Email delivery is intentionally a TODO. `deliver` config command prefix optionally
receives `purpose email code` (purpose `verify` or `reset`) after commit. The
default sends nothing. Wire delivery before using registration/recovery in PROD;
errors in the callback propagate to the host. Reset codes must be entered in the
browser that requested them. Codes are never placed in URLs or logs.

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
are AEAD-encrypted with tenant/user-associated data. Passwords use `bcrypt-tcl` at cost 12 with random salts. Inputs above 72 UTF-8
bytes or containing NUL characters are rejected rather than truncated. Native
MAC verification checks session, recovery, CSRF and TOTP codes; `tink-tcl` is
used without modifications.

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
winning. Run `::web::user::prune $store` periodically to delete expired sessions
and limit buckets. The host owns scheduling. Unverified account records remain
available for registration retry. The initial schema uses `CREATE IF NOT EXISTS`;
future schema upgrades require explicit migrations.

No OAuth, email transport, MFA backup-code system, roles, or account administration
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
`tmfa` 1.1.2, `tsession` 1.0.4, and `twebserver` for cryptographic random bytes.
Keep persistent keysets and databases outside the source and install directories.

Only the current storage and configuration format is supported. Unsalted email
indexes are incompatible; no fallback lookup or migration is included. Provision
a fresh account database for this release. Changing `email_hash_salt` or the MAC
key later invalidates email lookups. Preserve both with the encryption keysets.

With dependencies on `TCLLIBPATH`:

```sh
ENV=LOCAL tclsh tests/all.tcl
# Optional: run the same cases against an isolated PostgreSQL database:
WEB_USER_TEST_PG='-host 127.0.0.1 -port 55439 -database postgres -user test' \
  ENV=LOCAL tclsh tests/all.tcl
```

Tests exercise registration, recovery, session isolation/revocation, native crypto,
MFA/replay, persistent limits, configuration, and LOCAL/PROD output. PostgreSQL
runs use unique tenant namespaces; never point tests at a production database.

### Session cookies

`tsession` signs, reads and sets each mount's cookie using its own configuration
and the store's Tink MAC handle. Session records, absolute expiry and revocation
remain in `tpersist`; no in-memory session middleware is initialized. Cookies
are HttpOnly, SameSite=Lax, Path=/, and Secure with a `__Host-` name in PROD.

Request schemas use `topenapi` 0.2.0; see `assets/operations.json` and the mounting guide.
