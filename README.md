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
| **Keycloak 26.8** (realm `alensi`) | Authentication: passwords, MFA, passkeys, social/enterprise login, sessions. One **Organization per tenant**. Issues **lightweight access tokens** carrying only `iss`, `sub`, `aud`, `azp`, `sid`, `exp`, plus `organization` when a tenant is selected (`scope=organization:<alias>`). No roles or profile data. |
| **alensi-identity** (this service) | Authorization: users, applications, permissions, roles, the target hierarchy and grants. Verifies tokens locally against the realm JWKS. |
| **Postgres** | ACL data (`alensi_identity` database) and Keycloak's own database. |

### Tenancy

Each customer organization (e.g. an insurer) is a **tenant**, backed by a Keycloak Organization in the shared realm. A person can be a member of several tenants, each membership with its own status and expiry. Targets, grants and audit events carry `tenant_id`, enforced by composite foreign keys; roles and target types are either shared or owned by a tenant. A request acts in the tenant named by the token's `organization` claim or the `X-Alensi-Tenant` header, and the caller must be an active member. See [docs/access-model-insurance.md](docs/access-model-insurance.md#2-tenancy) for the reasoning.

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
| `company-admin` | a company | Create targets in the company; create, configure and assign the company's own roles; assign its assignable roles inside the company |
| `regional-admin` | a region | The same, inside the region |
| `branch-admin` | a branch | The same, inside the branch |
| `service` | `*` | Read any user's profile and permissions (backend services checking permissions for a user) |

Admin rules:
- A role's **assignable roles** decide what its holders may grant or revoke, and only on targets inside the one the role was granted on. Any role in any application can have them, so management chains are data. They are **transitive**: a manager can do whatever the roles below them can. Chains must not loop.
- Nobody changes their own access.
- Suspending a user requires scope over every grant that user holds.
- Reading another user's access is clipped to the caller's scope.

Roles can be **platform-wide** or **owned by a company** (a top-level target). Company roles are granted only inside their company and are managed by holders of `identity.roles.manage`, so each insurer defines its own ranks without seeing others'. Permissions flagged `limited` (e.g. `claims.approve`) carry a **limit per role and currency**. A user's limit on a target is the highest among their covering grants, and no limit means no authority.

Platform admins can add further admin levels, e.g. `team-admin`. See [docs/access-model-insurance.md](docs/access-model-insurance.md) for the alensi-insure model. Usernames listed in `alensi.identity.bootstrap-admins` get `platform-admin` on `*` the first time they are seen.

## API

`{user}` is a username or `me`. Querying another user needs `identity.permissions.read`.

| Method | Path | Purpose |
|---|---|---|
| GET/POST | `/api/tenants` | List your tenants / onboard a tenant: root target and Keycloak Organization (platform) |
| GET/POST | `/api/tenants/{tenant}/members` | Members (tenant admins) |
| PUT/DELETE | `/api/tenants/{tenant}/members/{username}` | Suspend, reactivate or set expiry of a membership / remove it with all its grants |
| GET | `/api/tenants/{tenant}/audit-events` | The tenant's audit trail (tenant admins) |
| GET | `/api/users/me` | Caller's profile |
| GET | `/api/users/username/{username}`, `/api/users/id/{id}` | Profile (`identity.users.read`) |
| PUT | `/api/users/username/{username}/access` | Suspend or reactivate a whole account across all tenants (platform-only) |
| GET | `/api/users/{user}/applications/{app}/permissions?targetCode=&targetType=&compressed=` | Permission map `type -> target -> [permissions]` |
| GET | `/api/users/{user}/applications/{app}/permissions/{permission}` | `{"allowed": bool}` on any target |
| GET | `/api/users/{user}/applications/{app}/permissions/{permission}/targets/{target}?amount=&currency=` | `{"allowed": bool, "limits": [...]}` on a target (inherits from ancestors; limits only for limited permissions) |
| GET | `/api/users/{user}/applications/{app}/permissions/{permission}/targets?compressed=` | Target codes, or `["*"]` |
| GET | `/api/users/{user}/applications/{app}/targets?targetType=` | Targets the user has any grant on |
| GET/POST | `/api/applications`, `/api/applications/{app}/permissions` | Catalog (writes are platform-only) |
| GET/POST | `/api/applications/{app}/roles` | Roles; `owner` creates a company role (`identity.roles.manage` on the company) |
| PUT | `/api/applications/{app}/roles/{role}/assignable-roles?owner=` | Set which roles an admin role may assign |
| PUT | `/api/applications/{app}/roles/{role}/limits?owner=` | Set a role's limits per limited permission and currency |
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

Any Keycloak client that calls this service needs three protocol mappers, all with *Add to lightweight access token* enabled: an **audience** mapper for `alensi-identity`, a **subject (`sub`)** mapper (Keycloak 26.8 drops `sub` from lightweight tokens by default), and an **organization membership** mapper. The client also needs `organization` as an optional client scope. The `alensi-identity` service account needs realm-management `view-users`, `query-users`, `manage-organizations` and `manage-users`; Keycloak requires the last one to add organization members.

## Status

This repository is a security-focused demonstration and learning platform. Features and implementation details may evolve as additional identity and access management patterns are explored.
