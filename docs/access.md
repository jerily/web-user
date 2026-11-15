# Groups and permissions

`web-user` owns tenant-scoped group membership and permission grants. A host
supplies configuration, then calls `sync_access` during initialization or an
explicit maintenance task. Request handlers only read the saved grants.

```ini
[groups]
admin = mira@example.com, rowan@example.com
moderator = alex@example.com

[permissions]
admin = forum.moderate
moderator = forum.moderate
```

These are ordinary INI sections. Each value is a comma-separated string. After
`tconfig` reads the file, pass the two dictionaries to:

```tcl
::web::user::initdb $connection
::web::user::sync_access $store [dict get $config groups] [dict get $config permissions]
```

The sync validates all input first, then replaces this tenant's groups,
memberships, and permission grants in one transaction. Removing an email, group,
or permission and syncing again revokes that access. An empty configuration
removes all grants for the tenant. Repeated syncs are safe. Other tenants are
untouched. Group names use lowercase letters, digits, underscores, and hyphens;
permission names also allow dots and colons. There are no wildcard grants or
implicit privileges attached to the name `admin`.

Membership is stored using the account package's keyed email index, not plaintext
addresses. This lets a site configure its first administrator before that person
registers. Only an active account with a verified matching email receives the
grants. Changing email reevaluates membership against the current account email.
Keep the account MAC key and email hash salt stable as usual.

```tcl
set user [::web::user::current_user $accountMount $request $context]
if {$user ne {} && [::web::user::has_permission $store [dict get $user id] forum.moderate]} {
    # Allow this action on the server.
}
```

`groups $store $userId` returns sorted group names; `permissions $store $userId`
returns their combined, deduplicated permission names. `has_permission` returns a
boolean. They read current account state and grants rather than permissions saved
in cookies, so a successful sync takes effect on the next request, including
existing sessions. Anonymous, unverified, inactive and deleted accounts have no
group permissions.

`example-community` syncs at startup. `ttrek.sh` calls the same function through
its private `task_sync_access` patch task. Neither approach needs a separate
authorization package or a request-time schema change.

## Content editing

`wiki.edit` allows creating and editing wiki pages, including a wiki-backed
homepage. `blog.edit` allows creating and editing blog posts. They are independent
of each other and of `forum.moderate`.

```ini
[groups]
editor = mira@example.com

[permissions]
editor = wiki.edit, blog.edit
```

Bind the permission to the content package's authorization callback:

```tcl
::web::wiki::mount $router -store $wikiStore \
    -authorize [list ::web::user::authorize_permission $accountMount wiki.edit] \
    -csrf [list ::web::user::csrf $accountMount] -config {allow_create true}
::web::blog::mount $router -store $blogStore \
    -authorize [list ::web::user::authorize_permission $accountMount blog.edit] \
    -csrf [list ::web::user::csrf $accountMount] -config {allow_create true}
```

The adapter uses the signed account session and checks current grants on every
call. The content packages use the same policy to generate edit/create links and
to authorize GET/POST editor routes. A valid CSRF token alone does not grant access.

`users.manage` grants the [user administration directory](admin.md), linked from
Account. Add it explicitly to the administrator group; forum moderation and
content editing permissions do not grant access to this page.
