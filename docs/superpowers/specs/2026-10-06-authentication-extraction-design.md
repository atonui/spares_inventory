# Authentication route extraction

## Intent and success criteria

Extract authentication, profile and session HTTP routes from the live inventory application's oversized `main.py`. Make the backend easier to navigate without changing user-visible behaviour. The user approved authentication first, with administration in a later PR.

Success means the routes live in a focused module, their request schemas live in a focused schema module, and `main.py` composes the router. Existing API contracts, permissions, session validation, transactions, audit records, cookies, CSRF and rate limits remain unchanged. No production database access, migration, UI change or deployment is required.

## Approach

Follow `backend/routes/work_orders.py`: a router factory receives explicit application dependencies. Move the existing endpoint bodies with minimal edits to resolve those dependencies. Do not introduce a new authentication framework, service hierarchy, dependency container, or global application singleton.

Extracting both authentication and administration together would enlarge the review and regression surface. Extracting only helper functions would leave the endpoint clutter in `main.py`. Authentication routes and their schemas are the first coherent boundary.

## Files and responsibilities

- `backend/routes/auth.py`: `create_auth_router(...)` constructs and returns an `APIRouter`, registers the 14 existing routes below, and contains their HTTP handlers.
- `backend/schemas/auth.py`: move `UserProfileUpdate`, `PasswordChange`, `ForgotPasswordRequest`, `ResetPasswordRequest`, and `UserLogin` unchanged. Move `UserResponse` unchanged as well: `/api/me` needs it and existing user-administration routes continue to import this same class through `main.py`.
- `main.py`: import the schema classes and register the authentication router once. Retain application setup, shared authentication/CSRF dependencies, credential and email helpers, logging setup, limiter, security configuration and transaction composition.
- Regression tests: add focused extraction/contract coverage and adapt only tests that depend on a handler's former location. Keep existing behaviour assertions.

No module in this extraction imports `main`. Shared dependencies remain in `main.py` for this PR so other routers keep the same dependency identity and existing override support.

## Exact route scope

| Method | Path |
|---|---|
| GET | `/api/csrf-token` |
| GET, PUT | `/api/profile` |
| POST | `/api/profile/change-password` |
| POST | `/api/auth/revoke-other-sessions` |
| POST | `/api/forgot-password` |
| POST | `/api/reset-password` |
| GET | `/api/verify-reset-token/{token}` |
| POST | `/api/auth/login` |
| GET | `/api/auth/sessions` |
| DELETE | `/api/auth/sessions/{session_id}` |
| POST | `/api/auth/sessions/revoke-all` |
| POST | `/api/auth/logout` |
| GET | `/api/me` |

This table represents 14 method/path operations. No user-administration, superadmin, stock, equipment, reporting or work-order routes move in this PR.

## Dependency boundary

The factory takes explicit named dependencies for connection acquisition, the authenticated writer owner, current-user and CSRF dependencies, CSRF generation, password hashing/verification, security configuration, reset-email delivery, standalone activity logging, endpoint logging, borrowed mutation activity recording, the existing limiter, application logger, and cookie security configuration. Use a scalar or callable for cookie configuration; do not hand the router the entire application module.

Use the actual `get_current_user` and `verify_csrf` callables in `Depends`, preserving FastAPI's override keys. Runtime collaborators that tests or operational configuration replace must remain late-bound through small callbacks in the composition root, rather than capturing stale values during router creation. In particular, changing `main.DATABASE` must still redirect connection acquisition, and monkeypatching email/hash/audit collaborators must remain effective where existing tests require it.

Preserve handler names, signatures and docstrings that affect route names and OpenAPI operation IDs. Preserve response models, schema names, route metadata, decorator ordering and registration semantics. Do not add tags or prefixes that alter the API contract. Retain the existing limiter instance, limits, Request handling and error-handler integration.

Do not introduce an import-time connection, database initializer, logger handler, limiter or environment-settings instance in the extracted modules. Router construction performs registration only.

## Behaviour and transaction preservation

Protected mutations continue to pass the original cookie token and actor ID into the existing authenticated transaction owner. Session checks occur after the writer lock; audit writes that belong to a mutation continue to use the same connection. No nested writer, extra commit, connection close, or standalone audit call is introduced inside that owner.

Public login/password-recovery operations keep their existing security, connection and audit behaviour. This is an extraction, not a repair of the public-auth concurrency limits deferred in PR52. Preserve login lockout rules, reset-token expiry and consumption, remember-me duration, session revocation, archived-user handling, password validation, cookies and exact existing HTTP error details.

Profile and session reads preserve their queries and responses. Preserve logout's transactional audit and cookie deletion. Retain the complete OpenAPI document, including schema and operation names.

Existing `main` schema imports remain available. Do not add compatibility aliases for every moved handler unless an actual direct consumer needs them; if needed, expose the already registered handler rather than registering a second route.

## Verification

Before extraction, capture the complete OpenAPI document under disposable configuration and run the baseline suite. Establish behaviour through HTTP tests before moving code; use existing coverage where it already proves a requirement.

Add meaningful checks for exactly one registration of each scoped operation, router ownership of moved handlers, dependency override identity, and imported-module isolation from `main` and database initialization. Add targeted HTTP coverage only for missing cookie, CSRF, rate-limit, profile, login/recovery or session behaviours discovered during the coverage inventory.

After extraction, compare complete OpenAPI documents for exact equality. Run the full Python regression suite and existing JavaScript tests, compilation, and whitespace checks. All databases used for tests are disposable; importing the application must use the established safe test bootstrap.

Request one independent whole-branch review after implementation, concentrating on dependency capture, limiter decoration, operation/schema identity, transaction ownership and accidental side effects. Publish a selected-file PR on verified current remote main; preserve upstream work, including merged PR52. Do not merge or deploy.

## Non-goals and remaining limits

Administration extraction follows in a separate PR. Shared authentication helpers, credential policy, email configuration, audit redesign, settings cleanup and further service extraction are deferred. The public-auth, read-response, external-effect and production-performance limits documented for PR52 remain unchanged.
