# User IDs

Registration creates `user_<ksuid>`, with a 27-character KSUID after `user_`.
The account keeps this identity after verification; its profile and session
subjects refer to the same ID. Public profile links use the complete ID.

Run `::web::user::migrate_user_ids $store` as an explicit maintenance task after
schema initialization. The store must use the site's existing tenant and keys.
Run it with account traffic paused so in-flight registration or session writes
cannot race the identity replacement.

The migration prefixes existing account and pending-registration IDs, updates
profiles and session subjects, and re-encrypts email, password hashes, profile
names, MFA secrets and pending authenticator setup secrets with their new
associated data. Browser tokens and verification/reset codes remain valid.
Email-based group membership and permissions are preserved. It returns counts
for users, registrations, profiles and sessions; repeated runs return zero.

All changes for the tenant commit in one transaction. Destination collisions,
unreadable ciphertext or concurrent record changes abort the run. Other tenants
and forum records are not touched.

In `ttrek.sh`, invoke the private patch task:

```json
{"source":"ttrek.patch","task":"task_migrate_user_ids"}
```

Locally, run `ttrek run -script initdb-local`, then
`ttrek run -script migrate-user-ids-local`.
