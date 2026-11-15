# User administration

The **Account → Manage users** link opens `<prefix>/admin/users` for accounts
with `users.manage`. The default prefix is `/user`. Grant it explicitly through
the same [groups and permissions](access.md) configuration:

```ini
[groups]
admin = mira@example.com

[permissions]
admin = users.manage, forum.moderate, wiki.edit, blog.edit
```

Synchronize the configuration through the host's initialization or maintenance
task. `example-community` syncs on restart; `ttrek.sh` uses `task_sync_access`.
Only active, verified accounts with the grant can open the page. The server
checks it on every request, so removal takes effect for existing sessions too.
The name `admin`, signing in, or holding a forum/editor permission does not
implicitly grant user administration.

The directory shows every registered account in the current tenant, with 50
accounts per page. Choose **Recently signed in** (the default), **Recently
active**, or **Newest registrations**. Each order is descending with the user ID
breaking ties, and pagination retains the chosen order:

- Name, email and optional username, with inactive/unverified status labels.
- Registration date, last successful sign-in, and last visit in UTC.
  A timestamp that has not been recorded displays **Not recorded**.
- Whether authenticator MFA is enabled. An unfinished setup is still Off.
- Configured groups matched to the account's current email. These assignments
  remain visible for inactive/unverified accounts, whose grants are ineffective.

Pending registrations that have not become accounts are not part of the list.
This first administration page is a directory only: it has no account mutation
routes, and POST requests receive 405. It does not expose password hashes,
authenticator secrets, session tokens or accounts from another tenant. Responses
are private and uncached. Query parameters accept a positive `page` number and
`sort=last_login`, `sort=last_visit`, or `sort=registered`.

The page extends the mount's configured `page.html.jinja` and can be customized
through the `admin-users.html.jinja` named template. It supplies `admin_view`,
`can_manage_users` and `signed_in` as true typed booleans; the regular account
form supplies `admin_view` as false. The package serves scoped styling at
`<prefix>/_assets/admin.css`, with a scrollable table on small screens.

Run the explicit package `initdb` maintenance step when deploying this version
to add `last_login_at`, `last_seen_at`, and the indexes for all three orders. Requests do
not create schema or synchronize access configuration.

Successful password-only login records `last_login_at`; with MFA, it is recorded
only after the authenticator succeeds. Failed attempts and session rotation for
password or MFA settings do not change the sign-in timestamp.

`current_user` and the shared account HTTP handler call `record_visit` after
resolving an active authenticated session. This updates `last_seen_at` at most
once per minute per tenant/user, using a conditional database update across
workers. Hosts already calling `current_user` for navigation or authorization
need no additional hook. It measures authenticated request activity, not how
long a tab stays open. Looking up another user's profile does not mark them active.
