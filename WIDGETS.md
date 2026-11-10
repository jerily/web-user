# Sharing widgets between packages

A host connects a widget provider to a named slot in a consumer's `widgets`
configuration dictionary. A widget is an HTML fragment, not a route or a page.
There is no global registry or additional package to initialize.

## Callback contract

```tcl
{*}$commandPrefix $properties $request $context
# Returns an HTML fragment as a Tcl string.
```

- `commandPrefix` is a trusted Tcl command list supplied by the host. Bind the
  provider's mount and widget name with `list`; do not construct executable text.
- `properties` is an ordinary dictionary whose keys belong to that widget's
  documented contract. For a profile, it contains `user_id`.
- `request` and `context` are the consumer's current request and trusted context,
  passed through unchanged. A provider may use them for access decisions.
- The provider owns its data access, template and escaping. It must enforce its
  visibility policy and escape every user-controlled value before returning HTML.
- The consumer inserts this trusted fragment with `safe`, without escaping it a
  second time. It must never treat request parameters as widget callbacks or markup.
- An absent or empty callback uses the consumer's fallback. Provider errors
  propagate to the host's normal error handler.

Rendering a widget does not write records, set cookies, register routes or change
response headers. Keep assets owned by their package and compatible with the
host's content security policy. The profile widget needs no additional assets.
Cache results only within the current render, keyed by all properties that affect
them; never reuse personalized fragments across requests or tenants.

## Connect the profile widget to a forum

After mounting accounts, the host binds the provider and passes it to the forum:

```tcl
set accounts [::web::user::mount $router -store $store -config $accountConfig]
set forumConfig [dict create prefix /forum widgets [dict create \
    profile [list ::web::user::widget $accounts profile]]]
::web::forum::mount $router -store $store -user $accounts -config $forumConfig
```

The forum invokes its `profile` slot with `dict create user_id $authorId` for topic
lists, topic authors and replies. It caches repeated authors during one page
render. Without a provider, it displays `Member`. It does not query profile tables
or decrypt names. Another provider can replace the callback without forum changes:

```tcl
proc ::site::member_badge {properties request context} {
    # Load authorized public data for [dict get $properties user_id].
    # Render an escaped HTML fragment with the site's template engine.
}
dict set forumConfig widgets profile ::site::member_badge
```

Other packages can use the same callback contract and document their own slot
names and property dictionaries.

## web-user profile provider

```tcl
set html [::web::user::widget $accounts profile \
    [dict create user_id $authorId] $request $context]
```

`profile` accepts only `user_id`. It resolves that ID in the account mount's
own tenant and supplies the first name to `profile.html.jinja` as `display_name`.
The result is a small escaped name label. Missing users, unverified users and
users without names display `Member`. Email, surname and credentials are never
included in the widget's template data. Unknown widget names are errors.

The host may override `profile.html.jinja` through the account mount's existing
`templates` property. Keep `{{ display_name }}` escaped. The provider's
`public_profile $store $userId` API returns the same public data dictionary;
`current_user` returns names only for the authenticated user's own account.

## Name collection and existing accounts

Set `collect_names true` in the web-user store configuration. It defaults to
false. When enabled, registration requires both names, each trimmed and limited
to 100 characters without control characters. Unicode and punctuation are
accepted. When disabled, the registration form omits names and the server rejects
submitted name fields; the profile-edit endpoint is not mounted.

For example-community, tconfig reads this from `config.ini`:

```ini
[account]
collect_names = true
```

Existing members can use **Your account → Edit profile** (`/user/profile`) to add
or correct names. GET and POST require a fully authenticated session; POST also
requires CSRF validation and passes the normal account rate limits. Updated
names appear on existing forum posts because widgets resolve the current profile.

Names are encrypted with the account's Tink AEAD key in `web_user_profiles`,
bound to the tenant, user ID and field. Run `::web::user::initdb` before serving the
new version: it adds this table without changing existing accounts. LOCAL
example-community initializes it automatically; for PROD run the normal explicit
`--initdb true` maintenance step before starting workers. Existing accounts keep
their IDs, passwords, sessions and posts and use `Member` until names are saved.
