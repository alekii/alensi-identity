-- Limited permissions (e.g. claims.approve) carry a monetary limit per role and currency.
ALTER TABLE permissions ADD COLUMN limited BOOLEAN NOT NULL DEFAULT FALSE;

-- Company-owned roles: owner is a top-level target (a company). Such roles can only be granted
-- inside the owner's subtree. NULL owner = platform-wide role.
ALTER TABLE roles ADD COLUMN owner_target_id BIGINT REFERENCES targets (id) ON DELETE CASCADE;
ALTER TABLE roles DROP CONSTRAINT roles_application_id_code_key;
CREATE UNIQUE INDEX roles_application_code_owner_key ON roles (application_id, code, owner_target_id) NULLS NOT DISTINCT;

-- No row for a currency means no authority in that currency. max_amount NULL means unlimited.
CREATE TABLE role_permission_limits (
    role_id       BIGINT      NOT NULL,
    permission_id BIGINT      NOT NULL,
    currency      VARCHAR(3)  NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    max_amount    NUMERIC(19, 2) CHECK (max_amount IS NULL OR max_amount >= 0),
    PRIMARY KEY (role_id, permission_id, currency),
    FOREIGN KEY (role_id, permission_id) REFERENCES role_permissions (role_id, permission_id) ON DELETE CASCADE
        DEFERRABLE INITIALLY DEFERRED
);

INSERT INTO permissions (application_id, code, description)
SELECT id, 'identity.roles.manage', 'Create and configure roles owned by a company within scope, and assign them'
FROM applications
WHERE code = 'alensi-identity';

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
         JOIN permissions p ON p.application_id = r.application_id AND p.code = 'identity.roles.manage'
WHERE r.code IN ('platform-admin', 'company-admin')
  AND r.owner_target_id IS NULL;
