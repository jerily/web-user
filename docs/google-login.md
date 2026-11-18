# Google Login

Google Login is optional in web-user 0.6.0. OAuth2/OIDC is implemented by
`pure-tcl-oauth2-client`, with tjson JSON and Tink JWT verification. Call the usual
`::web::user::initdb` during maintenance to add the identity and OAuth transaction
tables before enabling it. Startup and request handlers do not migrate schemas.

```tcl
set accounts [::web::user::mount $router -connection $connection -policy {tenant example} \
    -config [dict create prefix /user origin https://community.example \
        google_enabled true google_client_id $clientId \
        google_redirect_uri https://community.example/user/google/callback] \
    -secret_config [dict create aead_keyset $aeadKeyset mac_keyset $macKeyset \
        email_hash_salt $emailHashSalt google_client_secret $clientSecret]]
```

`-secret_config` is a private, server-side option. It accepts `aead_keyset`, `mac_keyset`, `email_hash_salt` and `google_client_secret`.
With `-connection` and public `-policy`, mount registers and owns the Tink key handles;
the host continues to own the connection. Do not put credentials in public `properties`,
template data or logs. The returned mount dictionary and route callbacks contain
private configuration and must remain internal to the host. Public Google options
are `google_enabled` (default false), `google_client_id` and `google_redirect_uri`.
Blank enablement is treated as disabled. The callback must exactly equal the
configured origin plus mount prefix plus `/google/callback`. LOCAL permits
loopback HTTP; PROD requires HTTPS. Disabling Google hides the buttons and routes,
without deleting stored identity links.

The login and registration pages offer Google. POST `/google/start` checks the
session's CSRF token and origin; GET `/google/callback` verifies browser-bound
state, PKCE, nonce, issuer, audience, expiry, signing algorithm and signature.
Only the verified Google subject identifies the account. Both documented Google
issuer forms map to `https://accounts.google.com`. Subject identifiers are indexed
with the site's tenant-bound MAC. Tokens are discarded after verification.
Pending state/nonce/PKCE transactions use SQL and the site's persistent AEAD key.
All workers must share these keys and the database.

New identities may register with a verified Google email. Their password field
is empty, which explicitly means password login is disabled. Existing accounts
are **never automatically linked by email**. Sign into the existing account and
use “Link Google account” with the current password. Linking is CSRF protected,
bound to that session and account revision, and permits one Google identity per
account. A changed email claim never changes an existing account's address.
Profile names are copied only when enabled by site policy; a public username can
be chosen later through Edit profile.

Local authenticator requirements still apply after Google verification. Until the
OTP completes, the browser only has a two-factor challenge session. Passwordless
accounts can confirm their linked Google account from the account page, then set
a password, close the account or manage MFA within five minutes. This proof is
bound to the session; disabling MFA still requires its current unused OTP.
Accounts with a password continue to require that password for sensitive actions.
Password-reset email does not silently create a password for Google-only accounts.

Unlinking Google requires a current password and an existing password sign-in
method, revokes other sessions, and rotates this session. Account closure removes
identity links. If Google-only users lose access to Google, a host needs its own
account-recovery policy; this package does not bypass their identity or MFA checks.
Google login uses a browser-session cookie; password-login “Stay signed in” behavior
remains independently available.

When removing mounted routes or replacing worker state, call
`::web::user::release $accounts` before closing the
connection; release destroys the client/store and unregisters mount-owned keys.
Ordinary `::web::user::prune` includes a bounded OAuth cleanup pass. Never log callback query strings or private mount dictionaries.

In Google Cloud configure a Web application OAuth client and its consent audience,
including test users when applicable. Register the exact callback above. The
standalone OAuth examples and a host account mount use different callback paths.
See [Google's OpenID Connect documentation](https://developers.google.com/identity/openid-connect/openid-connect)
and the `pure-tcl-oauth2-examples` README for the complete local walkthrough.
