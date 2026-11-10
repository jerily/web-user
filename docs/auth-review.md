# Marketplace authentication review (OAuth excluded)

Reviewed the local `jerily-webserver` marketplace account code on 2026-11-10:
`apps/user-auth-commons/src/user_auth_store.cpp`, `crypto_support.cpp`, and the
browser registration/authentication routes under `apps/user-registration-lambda`
and `apps/user-authenticate-lambda`. This is a source review of those flows, not a
claim to have audited all infrastructure or upstream gateway policies. No changes
were made to the marketplace.

The useful model is retained: pending email verification, authenticated identity,
pending second factor, pending setup, and pending recovery are separate states.
The marketplace encrypts private attributes, uses salted bcrypt, checks session
kinds/expiry, and binds setup confirmation to the authenticated user. The new
package adapts this model to Tcl, Tink, tpersist and mounted Jinja pages.

Findings addressed in the new package:

| Observation in reviewed code | New package behavior |
| --- | --- |
| `set_password_fields` trims password text (around line 397); recovery also trims it (1216). | Preserve UTF-8 password bytes exactly, enforce explicit length bounds, use native scrypt. |
| `confirm_two_factor_setup` accepts a matching submitted `rendered_demo_code` under `demo_expose_codes` (1091–1096), even if normal OTP verification fails. | LOCAL only changes display; it never changes acceptance rules. |
| Verification (roughly 790–880), MFA completion (925–984), and recovery (1212–1266) perform separate reads, writes and deletes. Concurrent consumers are not made atomic by these functions. | Transactional consumption, checked delete counts, unique email constraint, and user revision CAS. |
| `verify_totp_code` checks the current/adjacent time windows without a persisted used-step counter; `verify_two_factor` consumes only the pending session. | Persist last accepted OTP step per user; reject reuse even through another challenge. |
| `complete_password_reset` replaces the password and deletes its reset token, but these lines do not invalidate the account's other sessions. | Revoke all account sessions and recovery challenges in the same transaction; preserve MFA. |
| Recovery session IDs and verification codes are stored as directly usable values. | Store only purpose/tenant-bound keyed digests; generate credentials with crypto randomness. |
| No persistent attempt counter is visible in the reviewed store methods. Gateway protections may exist elsewhere. | Persistent per-peer, per-account/action and per-challenge limits, committed even when verification fails. |

`openacs-packages/sample-2fa/www/index.tcl` contains the requested `keyuri` example.
Its algorithm parameter is malformed (`params=...`), the issuer prefix is not
encoded, and it depends on NaviServer `ns_urlencode`. `tmfa::keyuri` is a generic
Tcl manager that validates type/counter/period/digits/algorithm, encodes UTF-8
issuer and account labels, emits `algorithm=...`, and canonicalizes Base32 without
padding. The web package generates a fresh random secret and uses `tqrcodegen`
for the QR image. It does not reuse the example's static secret.

References for the implementation decisions:
[Google Authenticator Key URI Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format)
and [OWASP password storage guidance](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#scrypt).
Tink has no password KDF; the new native password/random/comparison helpers in
`tink-tcl` explicitly use OpenSSL 3. AEAD and keyed digests remain Tink primitives.

Intentional boundaries: no OAuth, phone registration, magic-link login, marketplace
record migration, email sender, or MFA backup-code recovery system. The example
uses a member-can-edit content policy, not a marketplace role model. Production
email integration and deployment configuration remain host responsibilities.
