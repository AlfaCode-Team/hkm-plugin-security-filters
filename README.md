# hkm-plugin-security-filters

> HKM Kernel plugin — provides **`http.security_filters`**.
> Part of the [HKM Kernel](https://github.com/AlfaCode-Team/hkm-kernel) Gated Demand Architecture framework.

[![License: MIT](https://img.shields.io/badge/License-MIT-green)](LICENSE)
![PHP](https://img.shields.io/badge/PHP-8.4%2B-777bb4)

## Install

```bash
composer require alfacode-team/hkm-plugin-security-filters
# or, from a project:
hkm plugins add security-filters
```

## Capability

Provides `http.security_filters` — the 0.3 HTTP filters rebuilt as GDA pipeline
stages, in two flavours.

### Always-on hooks

Registered in `Provider::boot()`, they run on every request and self-gate on
their own configuration.

| Stage | Slot | Does |
|---|---|---|
| `SecurityHeadersStage` | `after.security` (10) | HSTS, CSP and the standard hardening headers |
| CORS | `after.security` | preflight + response headers, before any route resolves |

### Route filters — opt in per route

A route names them in its `filters[]`; `RouteFilterStage` runs them at the
`after.load` position, so they can resolve ports from the request-scoped
container.

| Alias | Stage | Does |
|---|---|---|
| `auth` | `RequireAuthStage` | Requires an authenticated `Identity` |
| `throttle:max,minutes` | `ApiRateLimitStage` | Rate limit — `throttle:60,1` = 60/minute |
| `shield` | `ShieldStage` | IP allow/deny rules |
| `hmac` | `HmacSignedStage` | Signed API **request** (machine to machine) — `X-Timestamp` + `X-Signature` over method, path, timestamp and raw body |
| `signed` | `SignedUrlStage` | Signed **link** from `signed_route()` (for a person) — verifies the HMAC over path + query, and the expiry |

```jsonc
{ "method": "POST", "path": "/api/tasks", "handler": "…@create",
  "filters": ["auth", "throttle:60,1"] }

{ "method": "GET",  "path": "/verify/{id:num}", "handler": "…@verify",
  "filters": ["signed"] }
```

`hmac` vs `signed`: use **`hmac`** for machine-to-machine calls that sign the
request itself; use **`signed`** for a URL you hand to a person — email
verification, one-time actions, unsubscribe endpoints. Both fail closed with an
empty `APP_KEY` / signing secret.

> A stage is wired as an always-on hook **or** as a route filter — never both.
> Registering the same stage twice runs it twice per request, and a rate limiter
> would double-count.

## Configuration

`HMAC_PROTECTED_PREFIX`, `HMAC_MAX_SKEW`, `REQUEST_SIGNING_SECRET`,
`RATE_LIMIT_PREFIX`, `RATE_LIMIT_MAX`, `RATE_LIMIT_WINDOW`, `SHIELD_RULES`,
`AUTH_PROTECTED_PATHS`, `CORS_*`, `HSTS_MAX_AGE`, `CONTENT_SECURITY_POLICY`.
`signed` uses `APP_KEY`.

## Documentation

- [CLAUDE.md](CLAUDE.md) — this plugin's contract, config and rules (start here).
- [Kernel guides](https://github.com/AlfaCode-Team/hkm-kernel/tree/main/docs/guides)
  — routing and filters are covered in `02_MODULE.md` and the routing guide.

## License

MIT — see [LICENSE](LICENSE).
