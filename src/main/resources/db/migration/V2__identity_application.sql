-- The identity service guards its own API with the same ACL model it serves.
INSERT INTO applications (code, name, description)
VALUES ('alensi-identity', 'Alensi Identity', 'Identity and access management API');

INSERT INTO permissions (application_id, code, description)
SELECT a.id, p.code, p.description
FROM applications a,
     (VALUES ('identity.users.read', 'Read other users'' profiles'),
             ('identity.permissions.read', 'Read other users'' permissions and targets'),
             ('identity.acl.manage', 'Manage applications, roles, targets and grants'),
             ('identity.audit.read', 'Read the audit log')) AS p (code, description)
WHERE a.code = 'alensi-identity';

INSERT INTO roles (application_id, code, name)
SELECT id, 'admin', 'Identity administrator' FROM applications WHERE code = 'alensi-identity';

INSERT INTO roles (application_id, code, name)
SELECT id, 'service', 'Service account (permission checks on behalf of users)' FROM applications WHERE code = 'alensi-identity';

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
         JOIN permissions p ON p.application_id = r.application_id
WHERE r.code = 'admin';

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
         JOIN permissions p ON p.application_id = r.application_id
WHERE r.code = 'service'
  AND p.code IN ('identity.users.read', 'identity.permissions.read');
