-- Users mirror Keycloak accounts. The id is the Keycloak subject (sub); Keycloak stays the
-- source of truth for credentials, MFA and sessions. Status/expiry are ACL-level controls.
CREATE TABLE users (
    id           UUID PRIMARY KEY,
    username     VARCHAR(255) NOT NULL UNIQUE,
    email        VARCHAR(320),
    name         VARCHAR(255),
    status       VARCHAR(16)  NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'SUSPENDED')),
    expires_at   TIMESTAMPTZ,
    last_seen_at TIMESTAMPTZ,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- An application is a consumer of permissions (one per Keycloak client / service).
CREATE TABLE applications (
    id          BIGSERIAL PRIMARY KEY,
    code        VARCHAR(64)  NOT NULL UNIQUE,
    name        VARCHAR(255) NOT NULL,
    description TEXT,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE TABLE permissions (
    id             BIGSERIAL PRIMARY KEY,
    application_id BIGINT       NOT NULL REFERENCES applications (id) ON DELETE CASCADE,
    code           VARCHAR(128) NOT NULL,
    description    TEXT,
    UNIQUE (application_id, code)
);

CREATE TABLE roles (
    id             BIGSERIAL PRIMARY KEY,
    application_id BIGINT       NOT NULL REFERENCES applications (id) ON DELETE CASCADE,
    code           VARCHAR(64)  NOT NULL,
    name           VARCHAR(255) NOT NULL,
    UNIQUE (application_id, code)
);

CREATE TABLE role_permissions (
    role_id       BIGINT NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    permission_id BIGINT NOT NULL REFERENCES permissions (id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

-- Targets scope grants (e.g. country > city > shop). Types form a hierarchy, and so do targets.
CREATE TABLE target_types (
    id        BIGSERIAL PRIMARY KEY,
    code      VARCHAR(64)  NOT NULL UNIQUE,
    name      VARCHAR(255) NOT NULL,
    parent_id BIGINT REFERENCES target_types (id)
);

CREATE TABLE targets (
    id         BIGSERIAL PRIMARY KEY,
    type_id    BIGINT       NOT NULL REFERENCES target_types (id),
    code       VARCHAR(64)  NOT NULL UNIQUE,
    name       VARCHAR(255) NOT NULL,
    parent_id  BIGINT REFERENCES targets (id),
    created_at TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- A grant gives a user a role on a target and all of its descendants.
-- A NULL target is the wildcard: the role applies on every target.
CREATE TABLE role_grants (
    id         BIGSERIAL PRIMARY KEY,
    user_id    UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role_id    BIGINT      NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    target_id  BIGINT REFERENCES targets (id) ON DELETE CASCADE,
    granted_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE NULLS NOT DISTINCT (user_id, role_id, target_id)
);

CREATE INDEX role_grants_user_idx ON role_grants (user_id);

CREATE TABLE audit_events (
    id          BIGSERIAL PRIMARY KEY,
    occurred_at TIMESTAMPTZ  NOT NULL DEFAULT now(),
    actor_id    UUID,
    action      VARCHAR(64)  NOT NULL,
    subject     VARCHAR(255) NOT NULL,
    details     TEXT
);

CREATE INDEX audit_events_occurred_at_idx ON audit_events (occurred_at DESC);
