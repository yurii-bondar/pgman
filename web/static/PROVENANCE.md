# Vendored admin UI JavaScript

Both files are unmodified upstream releases, compiled into the binary by
`web/static.go`. They are vendored rather than loaded from a CDN because
the admin UI has to work without egress to the public internet, and
because a third party that can change these files can drive every
control on the dashboard.

| File | Upstream | SHA-256 |
| --- | --- | --- |
| `htmx.min.js` | `https://unpkg.com/htmx.org@2.0.4/dist/htmx.min.js` | `e209dda5c8235479f3166defc7750e1dbcd5a5c1808b7792fc2e6733768fb447` |
| `htmx-ext-sse.js` | `https://unpkg.com/htmx-ext-sse@2.2.2/sse.js` | `83eca6fa0611fe2b0bf1700b424b88b5eced38ef448ef9760a2ea08fbc875611` |

## Updating

```sh
cd web/static
curl -sSLO https://unpkg.com/htmx.org@<version>/dist/htmx.min.js
curl -sSL -o htmx-ext-sse.js https://unpkg.com/htmx-ext-sse@<version>/sse.js
shasum -a 256 htmx.min.js htmx-ext-sse.js
```

Then update the versions and hashes above in the same commit. A diff
that changes a hash without changing the version documented next to it
is the thing a reviewer should stop on.

The two versions are not independent: `htmx-ext-sse` 2.x targets htmx
2.x. Upgrading one across a major means upgrading both, and the SSE
stream (`/events`, see `ui.go`) is what breaks if they disagree.
