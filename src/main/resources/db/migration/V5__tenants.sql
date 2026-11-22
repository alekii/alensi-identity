-- Explicit tenancy. A tenant (an insurer) maps to a Keycloak organization in a realm, owns a
-- subtree of targets, may define its own target types and roles, and has members. A person can be
-- a member of several tenants; each membership has its own status and expiry.

CREATE TABLE tenants (
    id                    BIGSERIAL PRIMARY KEY,
    code                  VARCHAR(64)  NOT NULL UNIQUE,
    name                  VARCHAR(255) NOT NULL,
    keycloak_realm        VARCHAR(64)  NOT NULL DEFAULT 'alensi',
    keycloak_organization VARCHAR(64)  NOT NULL,
    created_at            TIMESTAMPTZ  NOT NULL DEFAULT now(),
    UNIQUE (keycloak_realm, keycloak_organization)
);

-- Existing top-level targets become tenants.
INSERT INTO tenants (code, name, keycloak_organization)
SELECT code, name, lower(code)
FROM targets
WHERE parent_id IS NULL;

ALTER TABLE targets ADD COLUMN tenant_id BIGINT REFERENCES tenants (id) ON DELETE CASCADE;

WITH RECURSIVE tree AS (
    SELECT t.id, tn.id AS tenant_id
    FROM targets t
             JOIN tenants tn ON tn.code = t.code
    WHERE t.parent_id IS NULL
    UNION ALL
    SELECT child.id, tree.tenant_id
    FROM targets child
             JOIN tree ON child.parent_id = tree.id
)
UPDATE targets
SET tenant_id = tree.tenant_id
FROM tree
WHERE targets.id = tree.id;

ALTER TABLE targets ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE targets ADD CONSTRAINT targets_id_tenant_key UNIQUE (id, tenant_id);
-- Exactly one root target per tenant.
CREATE UNIQUE INDEX targets_tenant_root_key ON targets (tenant_id) WHERE parent_id IS NULL;

-- Target types may be shared (NULL tenant) or defined by a tenant, e.g. Jubilee's "area".
ALTER TABLE target_types ADD COLUMN tenant_id BIGINT REFERENCES tenants (id) ON DELETE CASCADE;
ALTER TABLE target_types DROP CONSTRAINT target_types_code_key;
CREATE UNIQUE INDEX target_types_code_tenant_key ON target_types (code, tenant_id) NULLS NOT DISTINCT;

-- Roles: company owner target becomes tenant.
ALTER TABLE roles ADD COLUMN tenant_id BIGINT REFERENCES tenants (id) ON DELETE CASCADE;
UPDATE roles r
SET tenant_id = t.tenant_id
FROM targets t
WHERE r.owner_target_id = t.id;
DROP INDEX roles_application_code_owner_key;
ALTER TABLE roles DROP COLUMN owner_target_id;
CREATE UNIQUE INDEX roles_application_code_tenant_key ON roles (application_id, code, tenant_id) NULLS NOT DISTINCT;

CREATE TABLE tenant_members (
    tenant_id  BIGINT      NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    user_id    UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    status     VARCHAR(16) NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'SUSPENDED')),
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, user_id)
);
CREATE INDEX tenant_members_user_idx ON tenant_members (user_id);

INSERT INTO tenant_members (tenant_id, user_id)
SELECT DISTINCT t.tenant_id, g.user_id
FROM role_grants g
         JOIN targets t ON t.id = g.target_id;

-- Grants carry their tenant. The database guarantees the target and the membership are in that
-- tenant; wildcard grants (no target) are platform grants with no tenant.
ALTER TABLE role_grants ADD COLUMN tenant_id BIGINT;
UPDATE role_grants g
SET tenant_id = t.tenant_id
FROM targets t
WHERE g.target_id = t.id;
ALTER TABLE role_grants
    ADD CONSTRAINT role_grants_target_in_tenant_fk FOREIGN KEY (target_id, tenant_id)
        REFERENCES targets (id, tenant_id) ON DELETE CASCADE,
    ADD CONSTRAINT role_grants_member_fk FOREIGN KEY (tenant_id, user_id)
        REFERENCES tenant_members (tenant_id, user_id) ON DELETE CASCADE,
    ADD CONSTRAINT role_grants_wildcard_is_platform CHECK ((target_id IS NULL) = (tenant_id IS NULL));
CREATE INDEX role_grants_tenant_idx ON role_grants (tenant_id);

ALTER TABLE audit_events ADD COLUMN tenant_id BIGINT REFERENCES tenants (id) ON DELETE SET NULL;
CREATE INDEX audit_events_tenant_idx ON audit_events (tenant_id, occurred_at DESC);
