# alensi-identity-spring-boot-starter

Permission checks against alensi-identity for Spring Boot services such as alensi-insure.
It uses the caller's own token, is tenant-aware and cached, and fails closed.

## Setup

```xml
<dependency>
    <groupId>io.alensi</groupId>
    <artifactId>alensi-identity-spring-boot-starter</artifactId>
    <version>0.1.0-SNAPSHOT</version>
</dependency>
```

Until it is published to a repository, install it locally with
`./mvnw -pl client install` in alensi-identity.

```yaml
spring.security.oauth2.resourceserver.jwt:
  issuer-uri: http://localhost:8180/realms/alensi
  audiences: alensi-insure                # this service's client id
alensi.identity.client:
  base-url: http://localhost:8090
  application: alensi-insure              # code in the identity catalog
  cache-ttl: 30s                          # default; how long a revoked grant can keep working here
```

Register the application first (Keycloak clients and catalog):
`python3 scripts/register_application.py catalog/alensi-insure.json`.

## Use

The bean `alensiAccess` (`AlensiAccess`) answers for the current request:

```java
access.require("claims.view", claim.branchCode());       // one record; throws AccessDeniedException

TargetScope scope = access.scope("claims.view");         // lists: filter in the query
List<Claim> visible = scope.all()
        ? claims.findByTenant(tenant)
        : claims.findByTenantAndBranchIn(tenant, scope.targets());

Decision d = access.decide("claims.approve", branch, amount, "KES");   // limited permissions, always live
if (!d.allowed()) {
    escalate(claim, d.limits());                          // e.g. the user's limit is KES 1,000,000
}

String tenant = access.tenant();                          // tenant code for this request, e.g. "JUB"
```

Declaratively, with `@EnableMethodSecurity`:

```java
@PreAuthorize("@alensiAccess.can('claims.view', #branch)")
public List<Claim> claimsFor(String branch) { ... }
```

## Behaviour

- **Whose permissions:** the caller's. Their token is forwarded to identity, so no service
  account is involved.
- **Which tenant:** the token's `organization` claim (sign in with `scope=organization:<alias>`)
  or the `X-Alensi-Tenant` request header, which is forwarded. Identity rejects tenants the caller
  isn't an active member of, and that surfaces here as `AccessDeniedException`.
- **Caching:** one permission map per user and tenant, for `cache-ttl`. It is expanded to
  descendant targets, so checks need no knowledge of the branch hierarchy. `decide(...)` is never
  cached. `evictCurrentUser()` drops a user's entry early.
- **Failure:** if identity is unreachable or errors, `AlensiIdentityException` propagates. A check
  never quietly succeeds or fails.
- **Background jobs:** there is no request or user token there, so use `AlensiIdentityClient`
  directly with the service account's token, e.g. `permissionsOf(username, token, tenant)`.
