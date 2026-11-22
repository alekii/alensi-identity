package io.alensi.identity.acl;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import io.alensi.identity.audit.AuditLog;
import io.alensi.identity.user.AccessGuard;
import io.alensi.identity.user.UserAccount;
import io.alensi.identity.web.BadRequestException;
import io.alensi.identity.web.ConflictException;
import io.alensi.identity.web.NotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Writes to the ACL catalog and grants. Every change is audited in the same transaction. */
@Service
@Transactional
public class AclAdminService {

    private final ApplicationRepository applications;
    private final PermissionRepository permissions;
    private final RoleRepository roles;
    private final TargetTypeRepository targetTypes;
    private final TargetRepository targets;
    private final RoleGrantRepository grants;
    private final AuditLog audit;
    private final AccessGuard access;

    AclAdminService(ApplicationRepository applications, PermissionRepository permissions, RoleRepository roles,
            TargetTypeRepository targetTypes, TargetRepository targets, RoleGrantRepository grants, AuditLog audit,
            AccessGuard access) {
        this.applications = applications;
        this.permissions = permissions;
        this.roles = roles;
        this.targetTypes = targetTypes;
        this.targets = targets;
        this.grants = grants;
        this.audit = audit;
        this.access = access;
    }

    public AclViews.ApplicationView createApplication(UserAccount actor, String code, String name, String description) {
        if (applications.existsByCode(code)) {
            throw new ConflictException("Application '%s' already exists".formatted(code));
        }
        Application application = applications.save(new Application(code, name, description));
        audit.record(actor.getId(), "application.created", code, name);
        return AclViews.ApplicationView.of(application);
    }

    public AclViews.PermissionView createPermission(UserAccount actor, String applicationCode, String code, String description) {
        Application application = application(applicationCode);
        if (permissions.existsByApplicationAndCode(application, code)) {
            throw new ConflictException("Permission '%s' already exists in '%s'".formatted(code, applicationCode));
        }
        Permission permission = permissions.save(new Permission(application, code, description));
        audit.record(actor.getId(), "permission.created", applicationCode + "/" + code, description);
        return AclViews.PermissionView.of(permission);
    }

    public AclViews.RoleView createRole(UserAccount actor, String applicationCode, String code, String name,
            Set<String> permissionCodes) {
        Application application = application(applicationCode);
        if (roles.existsByApplicationAndCode(application, code)) {
            throw new ConflictException("Role '%s' already exists in '%s'".formatted(code, applicationCode));
        }
        List<Permission> resolved = permissions.findByApplicationAndCodeIn(application, permissionCodes);
        if (resolved.size() != permissionCodes.size()) {
            Set<String> missing = new TreeSet<>(permissionCodes);
            resolved.forEach(permission -> missing.remove(permission.getCode()));
            throw new NotFoundException("Unknown permissions in '%s': %s".formatted(applicationCode, missing));
        }
        Role role = roles.save(new Role(application, code, name, new HashSet<>(resolved)));
        audit.record(actor.getId(), "role.created", applicationCode + "/" + code, "permissions=" + new TreeSet<>(permissionCodes));
        return AclViews.RoleView.of(role);
    }

    /** Replaces the roles that holders of {@code roleCode} may assign. */
    public AclViews.RoleView setAssignableRoles(UserAccount actor, String applicationCode, String roleCode,
            List<RoleRef> assignable) {
        Role role = role(applicationCode, roleCode);
        Set<Role> resolved = new HashSet<>();
        for (RoleRef ref : assignable) {
            resolved.add(role(ref.application(), ref.role()));
        }
        role.replaceAssignableRoles(resolved);
        audit.record(actor.getId(), "role.assignable-roles-updated", applicationCode + "/" + roleCode,
                "assignable=" + new TreeSet<>(assignable.stream().map(RoleRef::toString).toList()));
        return AclViews.RoleView.of(role);
    }

    public AclViews.TargetTypeView createTargetType(UserAccount actor, String code, String name, String parentCode) {
        if (targetTypes.existsByCode(code)) {
            throw new ConflictException("Target type '%s' already exists".formatted(code));
        }
        TargetType parent = parentCode == null ? null : targetType(parentCode);
        TargetType type = targetTypes.save(new TargetType(code, name, parent));
        audit.record(actor.getId(), "target-type.created", code, "parent=" + parentCode);
        return AclViews.TargetTypeView.of(type);
    }

    public AclViews.TargetView createTarget(UserAccount actor, String code, String name, String typeCode, String parentCode) {
        access.requireTargetManagement(actor, parentCode);
        if (targets.existsByCode(code)) {
            throw new ConflictException("Target '%s' already exists".formatted(code));
        }
        TargetType type = targetType(typeCode);
        Target parent = parentCode == null ? null : target(parentCode);
        TargetType expectedParentType = type.getParent();
        if (expectedParentType == null ? parent != null
                : parent == null || !parent.getType().getId().equals(expectedParentType.getId())) {
            throw new BadRequestException(expectedParentType == null
                    ? "Targets of type '%s' are top-level and cannot have a parent".formatted(typeCode)
                    : "Targets of type '%s' need a parent of type '%s'".formatted(typeCode, expectedParentType.getCode()));
        }
        Target target = targets.save(new Target(type, code, name, parent));
        audit.record(actor.getId(), "target.created", code, "type=%s parent=%s".formatted(typeCode, parentCode));
        return AclViews.TargetView.of(target);
    }

    /** Grants a role on a target and its descendants; a {@code null} target grants it on all targets. */
    public AclViews.GrantView grant(UserAccount actor, UserAccount user, String applicationCode, String roleCode,
            String targetCode) {
        Role role = role(applicationCode, roleCode);
        Target target = targetCode == null ? null : target(targetCode);
        access.requireCanAssign(actor, user, role.getId(), targetCode);
        boolean exists = target == null
                ? grants.existsByUserAndRoleAndTargetIsNull(user, role)
                : grants.existsByUserAndRoleAndTarget(user, role, target);
        if (exists) {
            throw new ConflictException("Grant already exists");
        }
        RoleGrant grant = grants.save(new RoleGrant(user, role, target, actor.getId()));
        audit.record(actor.getId(), "grant.created", user.getUsername(),
                "%s/%s on %s".formatted(applicationCode, roleCode, targetCode == null ? "*" : targetCode));
        return AclViews.GrantView.of(grant);
    }

    public void revoke(UserAccount actor, UserAccount user, long grantId) {
        RoleGrant grant = grants.findById(grantId)
                .filter(candidate -> candidate.getUser().getId().equals(user.getId()))
                .orElseThrow(() -> new NotFoundException("Grant %d not found for '%s'".formatted(grantId, user.getUsername())));
        access.requireCanAssign(actor, user, grant.getRole().getId(),
                grant.isWildcard() ? null : grant.getTarget().getCode());
        grants.delete(grant);
        audit.record(actor.getId(), "grant.revoked", user.getUsername(), "%s/%s on %s".formatted(
                grant.getRole().getApplication().getCode(), grant.getRole().getCode(),
                grant.isWildcard() ? "*" : grant.getTarget().getCode()));
    }

    private Application application(String code) {
        return applications.findByCode(code)
                .orElseThrow(() -> new NotFoundException("Application '%s' not found".formatted(code)));
    }

    private Role role(String applicationCode, String roleCode) {
        return roles.findByApplicationAndCode(application(applicationCode), roleCode)
                .orElseThrow(() -> new NotFoundException("Role '%s' not found in '%s'".formatted(roleCode, applicationCode)));
    }

    private TargetType targetType(String code) {
        return targetTypes.findByCode(code)
                .orElseThrow(() -> new NotFoundException("Target type '%s' not found".formatted(code)));
    }

    private Target target(String code) {
        return targets.findByCode(code)
                .orElseThrow(() -> new NotFoundException("Target '%s' not found".formatted(code)));
    }
}
