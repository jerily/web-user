# Package API manifest

Read [api.json](api.json) for mount options, callbacks, and ordered HTTP routes
in the `ttrek-web-api/1` format. Edit the manifest to change route declarations.
The account mount reads it through `web-core` at runtime.

## Availability and permissions

`when` selects routes as the router is built. Its `anyTrue` array names boolean
inputs declared in the manifest. For example, `/profile` is registered if
any of `policy.collect_names`, `policy.collect_display_name`, or
`policy.collect_username` is true. Missing inputs use their declared defaults.
Every visitor to that mount sees the same route table.

`access` describes the check a package handler enforces on each request.
`signedIn` requires a signed-in account, and `permission` names a required
group grant. The `/admin/users` route is always registered. Its handler checks
`users.manage` against the current account's tenant group memberships and grants.
Removing the grant takes effect on the next request, including for a signed-in
account. The handler also enforces sign-in, and group grants require an active,
verified account. Other endpoints may enforce their own session, CSRF, and
credential checks. See [groups and permissions](docs/access.md).

`operations` maps each documented HTTP method to an operation in a local JSON
file. A filename alone identifies the entire operation. A fragment identifies
one operation in a collection.
`schemas/operations.json#/email-login~1verify`, for example, addresses the
`email-login/verify` key. The package applies policy and account-specific field
requirements during validation.

## Composing a router

A router composition uses `mounts` to select packages by name and prefix. Each
package name and each prefix must be unique in that composition. The host
supplies mount configuration, installs packages in order, and registers its own
routes. This example mounts accounts at `/members` and protects a host route.

```json
{
  "format": "ttrek-web-api/1",
  "mounts": [{"package": "web-user", "prefix": "/members"}],
  "routerMiddleware": [],
  "routes": [{
    "id": "reports", "summary": "View staff reports.",
    "methods": ["GET"], "path": "/reports", "handler": ["::site::reports"],
    "access": {"permission": "reports.view"}
  }]
}
```

The host checks the declared grant before dispatching `::site::reports`. With
`web-user`, it can call `::web::user::authorize_permission` with the account
mount, permission, request, context, action and path.

## Mounting from a plan

`::web::user::mount` prepares resources, checks collisions, and installs
the plan on the supplied router. For a custom dispatcher, call
`::web::core::route_plan [::web::core::manifest web-user] $prefix $config $settings $policy`.
Use `package require web-core` when planning routes before the account handlers load.
The returned dictionary has three fields.

| Field | Contents |
| --- | --- |
| `paths` | All candidate paths, including disabled ones, for collision checks. |
| `middleware` | Ordered option dictionaries for `$router add_middleware {*}$layer`. |
| `routes` | Enabled routes in registration order. Each contains `id`, `methods`, `path`, `handler` and `options`. |

Paths in the manifest are relative to the mount. The empty string produces
the mount prefix itself and `"/"` produces its trailing-slash URL. Route plan
paths are ready to register. For a prepared account configuration, install them
with `::web::core::install $router $plan ::web::user::request_dispatch` to give
each handler its account request scope. The handler and both hooks are Tcl command
prefixes. Each string in a prefix is one literal word. A
`{"bind": "config"}` word carries the opaque mount value as one argument.

## Middleware

`routerMiddleware` accepts a sequence of enter/leave layers. Each layer needs
at least one hook. A route can also supply its own `enter_proc`, `leave_proc`,
or both. This excerpt installs request tracing for the router and a quota
for the submission route.

```json
{
  "routerMiddleware": [
    {"enter_proc": ["::example::trace_start"], "leave_proc": ["::example::trace_finish"]}
  ],
  "routes": [
    {
      "id": "submit", "summary": "Accept a submission.",
      "methods": ["POST"], "path": "/submit", "handler": ["::example::submit"],
      "enter_proc": ["::example::check_quota", "submissions"]
    }
  ]
}
```

`tpathexp` 1.2 calls enter hooks with `context request` and expects an updated
request. Leave hooks receive `context request response` and return an updated
response. A handler receives `request context params` after its bound words.
Router enter hooks run in registration order, followed by the route enter hook
and handler. The route leave hook runs first, then router leave hooks in reverse.
Router layers also run for automatic 404 and 405 responses. A structured HTTP
abort runs the leaves of reached layers. Ordinary Tcl errors propagate directly.

Router-wide layers affect every mount on the supplied router. Registration
appends each layer, including repeated registrations. A host composing several
packages can collect their plans and install shared layers once in the intended
order. The account package declares an empty list of router-wide layers.
