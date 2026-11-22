# Alensi ACL

**Identity & Access Management Platform**

Alensi ACL is a security-focused identity and access management platform designed to demonstrate modern authentication, authorization, and secure API access patterns.

## Focus

This project is focused entirely on security and explores how to build reliable identity and access controls for users, applications, and services.

## Demonstrates

- **Keycloak** — Identity and access management integration
- **OAuth 2.0 / OpenID Connect** — Modern delegated authorization and authentication
- **JWT** — Token-based authentication for secure APIs
- **RBAC** — Role-based access control and permission management
- **MFA** — Multi-factor authentication for stronger account protection
- **Passkeys / WebAuthn** — Passwordless, phishing-resistant authentication
- **User management** — Managing identities, accounts, and access lifecycle
- **Service-to-service authentication** — Secure communication between backend services
- **Audit logging** — Tracking security-sensitive events and access activity
- **Secure API access** — Protecting APIs with authentication and authorization policies

## Security Goals

- Centralize identity and access management
- Apply least-privilege authorization
- Support strong, phishing-resistant authentication
- Secure both user-facing and machine-to-machine access
- Provide visibility into security-relevant activity through audit logs

## Architecture

| Component | Responsibility |
|---|---|
| **Keycloak 26.8** (realm `alensi`) | Authentication: passwords, MFA, passkeys, social/enterprise login, sessions. Issues **lightweight access tokens** carrying only `iss`, `sub`, `aud`, `azp`, `sid`, `exp`, with no roles or profile data. |
| **alensi-identity** (this service) | Authorization: users, applications, permissions, roles, the target hierarchy and grants. Verifies tokens locally against the realm JWKS. |
| **Postgres** | ACL data (`alensi_identity` database) and Keycloak's own database. |

### ACL model

- **Application**: a consumer of permissions, e.g. `alensi-pay`.
- **Permission**: an action in an application, e.g. `payments.refund`.
- **Role**: a named set of an application's permissions.
- **Target**: what a grant is scoped to (country, city, merchant, ...). Target types and targets both form hierarchies.
- **Grant**: a user holds a role on a target **and all of its descendants**. A grant without a target is the wildcard `*` and applies on every target.
- Users are mirrored from Keycloak by `sub` and provisioned on first sight through the Keycloak Admin API. They can be suspended or given an expiry date here, which takes effect on the next request and also clears their effective permissions.

The service authorizes its own API with the same model, through the seeded `alensi-identity` application. Administration is **delegated down the target tree**:

| Role | Typically granted on | Can |
|---|---|---|
| `platform-admin` | `*` | Everything, including the catalog (applications, permissions, roles, target types), top-level targets, `*` grants and the audit log |
| `company-admin` | a company | Create targets in the company, and assign its assignable roles inside it |
| `regional-admin` | a region | The same, inside the region |
| `branch-admin` | a branch | The same, inside the branch |
| `service` | `*` | Read any user's profile and permissions (backend services checking permissions for a user) |

Admin rules:
- A role's **assignable roles** decide what its holders may grant or revoke, and only on targets inside the one their admin role was granted on.
- Nobody changes their own access.
- Suspending a user requires scope over every grant that user holds.
- Reading another user's access is clipped to the caller's scope.

Platform admins can add further admin levels, e.g. `team-admin`. See [docs/access-model-insurance.md](docs/access-model-insurance.md) for the alensi-insure model. Usernames listed in `alensi.identity.bootstrap-admins` get `platform-admin` on `*` the first time they are seen.

## API

`{user}` is a username or `me`. Querying another user needs `identity.permissions.read`.

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/users/me` | Caller's profile |
| GET | `/api/users/username/{username}`, `/api/users/id/{id}` | Profile (`identity.users.read`) |
| PUT | `/api/users/username/{username}/access` | Suspend, reactivate or set expiry (scope over all of the user's grants) |
| GET | `/api/users/{user}/applications/{app}/permissions?targetCode=&targetType=&compressed=` | Permission map `type -> target -> [permissions]` |
| GET | `/api/users/{user}/applications/{app}/permissions/{permission}` | `{"allowed": bool}` on any target |
| GET | `/api/users/{user}/applications/{app}/permissions/{permission}/targets/{target}` | `{"allowed": bool}` on a target (inherits from ancestors) |
| GET | `/api/users/{user}/applications/{app}/permissions/{permission}/targets?compressed=` | Target codes, or `["*"]` |
| GET | `/api/users/{user}/applications/{app}/targets?targetType=` | Targets the user has any grant on |
| GET/POST | `/api/applications`, `/api/applications/{app}/permissions`, `/api/applications/{app}/roles` | Catalog (writes are platform-only) |
| PUT | `/api/applications/{app}/roles/{role}/assignable-roles` | Set which roles an admin role may assign (platform-only) |
| GET/POST | `/api/target-types`, `/api/targets` | Target hierarchy (types platform-only; targets need `identity.targets.manage` on the parent) |
| GET/POST/DELETE | `/api/users/{username}/grants[/{id}]` | Grants (assignable roles, within scope) |
| GET | `/api/audit-events` | Audit log of ACL changes (`identity.audit.read`) |

Errors are returned as RFC 9457 problem details.

## Running locally

Requires Java 21 and Docker.

```bash
docker compose up -d          # Postgres on :5433, Keycloak on :8180 (admin console: admin/admin)
./mvnw spring-boot:run        # service on :8090
./mvnw test                   # unit tests + API tests on Testcontainers Postgres
```

Development realm users: `admin/admin` (bootstrap admin) and `alice/alice`. Clients: `alensi-web` (public, PKCE, plus password grant for local testing only) and `alensi-demo-service` (client credentials).

```bash
TOKEN=$(curl -s http://localhost:8180/realms/alensi/protocol/openid-connect/token \
  -d grant_type=password -d client_id=alensi-web -d username=admin -d password=admin | jq -r .access_token)
curl -s localhost:8090/api/users/me -H "Authorization: Bearer $TOKEN"
```

Any Keycloak client that calls this service needs two protocol mappers, both with *Add to lightweight access token* enabled: an **audience** mapper for `alensi-identity`, and a **subject (`sub`)** mapper. Keycloak 26.8 drops `sub` from lightweight tokens by default.

## Status

This repository is a security-focused demonstration and learning platform. Features and implementation details may evolve as additional identity and access management patterns are explored.
