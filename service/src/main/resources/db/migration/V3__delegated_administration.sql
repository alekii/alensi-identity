-- Delegated administration: an admin role lists the roles its holders may assign. Holders may
-- only assign them on targets inside the target their admin role was granted on.
CREATE TABLE role_assignable_roles (
    role_id            BIGINT NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    assignable_role_id BIGINT NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, assignable_role_id)
);

-- identity.acl.manage becomes the platform-only permission; admin becomes platform-admin.
UPDATE permissions
SET code        = 'identity.platform.manage',
    description = 'Manage the catalog (applications, permissions, roles, target types, top-level targets) and grant on all targets'
WHERE code = 'identity.acl.manage'
  AND application_id = (SELECT id FROM applications WHERE code = 'alensi-identity');

UPDATE roles
SET code = 'platform-admin',
    name = 'Platform administrator'
WHERE code = 'admin'
  AND application_id = (SELECT id FROM applications WHERE code = 'alensi-identity');

INSERT INTO permissions (application_id, code, description)
SELECT a.id, p.code, p.description
FROM applications a,
     (VALUES ('identity.users.manage', 'Grant and revoke assignable roles, suspend accounts, within scope'),
             ('identity.targets.manage', 'Create targets under targets within scope')) AS p (code, description)
WHERE a.code = 'alensi-identity';

-- Platform admins hold every identity permission.
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
         JOIN permissions p ON p.application_id = r.application_id
WHERE r.code = 'platform-admin'
ON CONFLICT DO NOTHING;

INSERT INTO roles (application_id, code, name)
SELECT a.id, r.code, r.name
FROM applications a,
     (VALUES ('company-admin', 'Company administrator'),
             ('regional-admin', 'Regional administrator'),
             ('branch-admin', 'Branch administrator')) AS r (code, name)
WHERE a.code = 'alensi-identity';

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
         JOIN permissions p ON p.application_id = r.application_id
WHERE r.code IN ('company-admin', 'regional-admin', 'branch-admin')
  AND p.code IN ('identity.users.read', 'identity.permissions.read', 'identity.users.manage', 'identity.targets.manage');

-- Chain of command. Business roles (e.g. alensi-insure agent) are added per application by a platform admin.
INSERT INTO role_assignable_roles (role_id, assignable_role_id)
SELECT admin.id, assignable.id
FROM roles admin
         JOIN roles assignable ON assignable.application_id = admin.application_id
WHERE (admin.code = 'company-admin' AND assignable.code IN ('regional-admin', 'branch-admin'))
   OR (admin.code = 'regional-admin' AND assignable.code = 'branch-admin');
