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

The directory shows every registered account in the current tenant, newest
first, with 50 accounts per page:

- Name, email and optional username, with inactive/unverified status labels.
- Registration date and time in UTC.
- Whether authenticator MFA is enabled. An unfinished setup is still Off.
- Configured groups matched to the account's current email. These assignments
  remain visible for inactive/unverified accounts, whose grants are ineffective.

Pending registrations that have not become accounts are not part of the list.
This first administration page is a directory only: it has no account mutation
routes, and POST requests receive 405. It does not expose password hashes,
authenticator secrets, session tokens or accounts from another tenant. Responses
are private and uncached. Query parameters accept only a positive `page` number.

The page extends the mount's configured `page.html.jinja` and can be customized
through the `admin-users.html.jinja` named template. It supplies `admin_view`,
`can_manage_users` and `signed_in` as true typed booleans; the regular account
form supplies `admin_view` as false. The package serves scoped styling at
`<prefix>/_assets/admin.css`, with a scrollable table on small screens.

Run the explicit package `initdb` maintenance step when deploying this version
to create the `(tenant, created_at, id)` registration-order index. Requests do
not create schema or synchronize access configuration.
