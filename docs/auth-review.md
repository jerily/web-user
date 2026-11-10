# Authentication design (OAuth excluded)

The account package separates pending email verification, authenticated sessions,
pending second-factor checks, authenticator setup and password recovery. A
pending session never grants an authenticated identity.

| Concern | Package behavior |
| --- | --- |
| Password handling | Preserve password text; require at least 15 characters and at most 72 UTF-8 bytes; reject NUL; use bcrypt at cost 12. |
| Session and recovery credentials | Generate 32 random bytes with twebserver; store tenant/purpose-bound Tink MAC digests. |
| Sensitive account fields | Encrypt email and authenticator secrets with Tink AEAD and bound associated data. |
| Concurrent account changes | Use transactions, checked challenge consumption and user revision checks. |
| Authenticator replay | Persist the last accepted TOTP step and reject reuse across sessions. |
| Password recovery | Consume the code once, revoke account sessions and preserve existing MFA. |
| Attempt limits | Persist peer, account/action and challenge counters independently of failed authentication transactions. |
| LOCAL diagnostics | Display development codes without changing verification, expiry or replay rules. |
| Session cookies | Use per-mount tsession signing, HttpOnly and SameSite=Lax; add Secure and a __Host- name in PROD. |

`tmfa::keyuri` creates the authenticator provisioning URI; `tqrcodegen` renders
its QR image. Each enrollment uses a fresh random secret. The package uses
Tink's existing AEAD and MAC APIs, bcrypt-tcl for passwords, and twebserver for
random bytes. Persist keys across workers and restarts.

Email delivery remains a host callback/TODO. OAuth, phone registration,
magic-link login, MFA backup codes, roles and account administration are outside
this package. Hosts own trusted origin/proxy configuration, TLS, delivery and
scheduled pruning. See [MOUNTING.md](../MOUNTING.md) for the API contract.
