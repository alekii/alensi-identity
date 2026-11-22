package io.alensi.identity.acl;

import java.math.BigDecimal;
import java.util.ArrayDeque;
import java.util.Collection;
import java.util.Deque;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;

import io.alensi.identity.audit.AuditLog;
import io.alensi.identity.tenant.Tenant;
import io.alensi.identity.tenant.TenantService;
import io.alensi.identity.user.AccessGuard;
import io.alensi.identity.user.UserAccount;
import io.alensi.identity.web.BadRequestException;
import io.alensi.identity.web.ConflictException;
import io.alensi.identity.web.NotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Writes to the ACL catalog and grants. Every change is authorized and audited in the same transaction. */
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
    private final TenantService tenants;

    AclAdminService(ApplicationRepository applications, PermissionRepository permissions, RoleRepository roles,
            TargetTypeRepository targetTypes, TargetRepository targets, RoleGrantRepository grants, AuditLog audit,
            AccessGuard access, TenantService tenants) {
        this.applications = applications;
        this.permissions = permissions;
        this.roles = roles;
        this.targetTypes = targetTypes;
        this.targets = targets;
        this.grants = grants;
        this.audit = audit;
        this.access = access;
        this.tenants = tenants;
    }

    public AclViews.ApplicationView createApplication(UserAccount actor, String code, String name, String description) {
        if (applications.existsByCode(code)) {
            throw new ConflictException("Application '%s' already exists".formatted(code));
        }
        Application application = applications.save(new Application(code, name, description));
        audit.record(actor.getId(), "application.created", code, name);
        return AclViews.ApplicationView.of(application);
    }

    public AclViews.PermissionView createPermission(UserAccount actor, String applicationCode, String code,
            String description, boolean limited) {
        Application application = application(applicationCode);
        if (permissions.existsByApplicationAndCode(application, code)) {
            throw new ConflictException("Permission '%s' already exists in '%s'".formatted(code, applicationCode));
        }
        Permission permission = permissions.save(new Permission(application, code, description, limited));
        audit.record(actor.getId(), "permission.created", applicationCode + "/" + code, "limited=" + limited);
        return AclViews.PermissionView.of(permission);
    }

    /**
     * Creates a shared role ({@code tenantCode == null}) or one owned by a tenant. Tenant roles cannot
     * carry platform-only permissions and cannot reuse a shared role's code.
     */
    public AclViews.RoleView createRole(UserAccount actor, String applicationCode, String code, String name,
            Set<String> permissionCodes, String tenantCode, List<LimitSpec> limits) {
        Tenant tenant = tenantCode == null ? null : tenants.tenant(tenantCode);
        access.requireTenantConfiguration(actor, tenant);
        Application application = application(applicationCode);
        if (tenant == null ? roles.existsByApplicationAndCode(application, code)
                : roles.existsByApplicationAndCodeAndTenantIsNull(application, code)
                        || roles.existsByApplicationAndCodeAndTenant(application, code, tenant)) {
            throw new ConflictException("Role '%s' already exists in '%s'".formatted(code, applicationCode));
        }
        List<Permission> resolved = permissions.findByApplicationAndCodeIn(application, permissionCodes);
        if (resolved.size() != permissionCodes.size()) {
            Set<String> missing = new TreeSet<>(permissionCodes);
            resolved.forEach(permission -> missing.remove(permission.getCode()));
            throw new NotFoundException("Unknown permissions in '%s': %s".formatted(applicationCode, missing));
        }
        if (tenant != null) {
            requireNoPlatformOnly(resolved);
        }
        Role role = roles.save(new Role(application, code, name, new HashSet<>(resolved), tenant));
        role.replaceLimits(resolveLimits(role, limits));
        audit.record(actor.getId(), tenant, "role.created", AclViews.RoleView.reference(role),
                "permissions=%s limits=%s".formatted(new TreeSet<>(permissionCodes), describe(limits)));
        return AclViews.RoleView.of(role);
    }

    /** Replaces a role's limits. A limited permission without a limit for a currency grants no authority in it. */
    public AclViews.RoleView setLimits(UserAccount actor, String applicationCode, String roleCode, String tenantCode,
            List<LimitSpec> limits) {
        Role role = role(applicationCode, roleCode, tenantCode);
        access.requireTenantConfiguration(actor, role.getTenant());
        role.replaceLimits(resolveLimits(role, limits));
        audit.record(actor.getId(), role.getTenant(), "role.limits-updated", AclViews.RoleView.reference(role), describe(limits));
        return AclViews.RoleView.of(role);
    }

    /**
     * Replaces the roles that holders of a role may assign; this is what makes a role a manager role.
     * Chains such as area manager → branch manager → sales manager → team lead → agent are built by
     * giving each role the next one down. A tenant role may list shared roles and its own tenant's
     * roles; a shared role may list shared roles only.
     */
    public AclViews.RoleView setAssignableRoles(UserAccount actor, String applicationCode, String roleCode,
            String tenantCode, List<RoleRef> assignable) {
        Role role = role(applicationCode, roleCode, tenantCode);
        access.requireTenantConfiguration(actor, role.getTenant());
        Set<Role> resolved = new HashSet<>();
        for (RoleRef ref : assignable) {
            Role target = role(ref.application(), ref.role(), ref.tenant() != null ? ref.tenant()
                    : role.isShared() || roleExists(ref.application(), ref.role(), null) ? null : tenantCode);
            if (target.isShared()) {
                if (!role.isShared()) {
                    requireNoPlatformOnly(target.getPermissions());
                }
            }
            else if (role.isShared() || !target.getTenant().getId().equals(role.getTenant().getId())) {
                throw new BadRequestException("'%s' cannot assign another tenant's role '%s'"
                        .formatted(AclViews.RoleView.reference(role), AclViews.RoleView.reference(target)));
            }
            resolved.add(target);
        }
        requireNoCycle(role, resolved);
        role.replaceAssignableRoles(resolved);
        audit.record(actor.getId(), role.getTenant(), "role.assignable-roles-updated", AclViews.RoleView.reference(role),
                "assignable=" + resolved.stream().map(AclViews.RoleView::reference).collect(Collectors.toCollection(TreeSet::new)));
        return AclViews.RoleView.of(role);
    }

    /**
     * Creates a shared target type ({@code tenantCode == null}, platform-only) or one private to a
     * tenant, e.g. Jubilee's {@code area} between region and branch. Tenant types cannot reuse a
     * shared type's code; their parent may be shared or the tenant's own.
     */
    public AclViews.TargetTypeView createTargetType(UserAccount actor, String code, String name, String parentCode,
            String tenantCode) {
        Tenant tenant = tenantCode == null ? null : tenants.tenant(tenantCode);
        access.requireTenantConfiguration(actor, tenant);
        if (tenant == null ? targetTypes.existsByCode(code)
                : targetTypes.existsByCodeAndTenantIsNull(code) || targetTypes.findByCodeAndTenant(code, tenant).isPresent()) {
            throw new ConflictException("Target type '%s' already exists".formatted(code));
        }
        TargetType parent = parentCode == null ? null : targetType(parentCode, tenant);
        TargetType type = targetTypes.save(new TargetType(code, name, parent, tenant));
        audit.record(actor.getId(), tenant, "target-type.created", code, "parent=" + parentCode);
        return AclViews.TargetTypeView.of(type);
    }

    /** Creates a target below {@code parentCode}, in the parent's tenant. Tenant roots come with the tenant. */
    public AclViews.TargetView createTarget(UserAccount actor, String code, String name, String typeCode,
            String parentCode) {
        if (parentCode == null) {
            throw new BadRequestException("Top-level targets are tenant roots; create a tenant instead");
        }
        access.requireTargetManagement(actor, parentCode);
        if (targets.existsByCode(code)) {
            throw new ConflictException("Target '%s' already exists".formatted(code));
        }
        Target parent = target(parentCode);
        TargetType type = targetType(typeCode, parent.getTenant());
        TargetType expectedParentType = type.getParent();
        if (expectedParentType == null ? parent != null
                : parent == null || !parent.getType().getId().equals(expectedParentType.getId())) {
            throw new BadRequestException(expectedParentType == null
                    ? "Targets of type '%s' are top-level and cannot have a parent".formatted(typeCode)
                    : "Targets of type '%s' need a parent of type '%s'".formatted(typeCode, expectedParentType.getCode()));
        }
        Target target = targets.save(new Target(type, code, name, parent));
        audit.record(actor.getId(), target.getTenant(), "target.created", code, "type=%s parent=%s".formatted(typeCode, parentCode));
        return AclViews.TargetView.of(target);
    }

    /**
     * Grants a role on a target and its descendants; a {@code null} target grants it on all targets
     * (platform grants). The role code resolves to the target's tenant's own role if it has one,
     * otherwise the shared role. The user becomes a member of the target's tenant if they are not one.
     */
    public AclViews.GrantView grant(UserAccount actor, UserAccount user, String applicationCode, String roleCode,
            String targetCode) {
        Target target = targetCode == null ? null : target(targetCode);
        Role role = roleForGrant(application(applicationCode), roleCode, target);
        access.requireCanAssign(actor, user, role, targetCode);
        boolean exists = target == null
                ? grants.existsByUserAndRoleAndTargetIsNull(user, role)
                : grants.existsByUserAndRoleAndTarget(user, role, target);
        if (exists) {
            throw new ConflictException("Grant already exists");
        }
        if (target != null) {
            tenants.ensureMember(actor, target.getTenant(), user);
        }
        RoleGrant grant = grants.save(new RoleGrant(user, role, target, actor.getId()));
        audit.record(actor.getId(), grant.getTenant(), "grant.created", user.getUsername(),
                "%s on %s".formatted(AclViews.RoleView.reference(role), targetCode == null ? "*" : targetCode));
        return AclViews.GrantView.of(grant);
    }

    public void revoke(UserAccount actor, UserAccount user, long grantId) {
        RoleGrant grant = grants.findById(grantId)
                .filter(candidate -> candidate.getUser().getId().equals(user.getId()))
                .orElseThrow(() -> new NotFoundException("Grant %d not found for '%s'".formatted(grantId, user.getUsername())));
        access.requireCanAssign(actor, user, grant.getRole(), grant.isWildcard() ? null : grant.getTarget().getCode());
        grants.delete(grant);
        audit.record(actor.getId(), grant.getTenant(), "grant.revoked", user.getUsername(), "%s on %s".formatted(
                AclViews.RoleView.reference(grant.getRole()), grant.isWildcard() ? "*" : grant.getTarget().getCode()));
    }

    private Role roleForGrant(Application application, String roleCode, Target target) {
        if (target != null) {
            var owned = roles.findByApplicationAndCodeAndTenant(application, roleCode, target.getTenant());
            if (owned.isPresent()) {
                return owned.get();
            }
        }
        return roles.findByApplicationAndCodeAndTenantIsNull(application, roleCode)
                .orElseThrow(() -> new NotFoundException("Role '%s' not found in '%s'%s".formatted(roleCode,
                        application.getCode(), target == null ? "" : " for '%s'".formatted(target.getCode()))));
    }

    private Set<RoleLimit> resolveLimits(Role role, List<LimitSpec> specs) {
        Set<RoleLimit> resolved = new HashSet<>();
        for (LimitSpec spec : specs == null ? List.<LimitSpec>of() : specs) {
            Permission permission = role.getPermissions().stream()
                    .filter(candidate -> candidate.getCode().equals(spec.permission()))
                    .findFirst()
                    .orElseThrow(() -> new BadRequestException("Role '%s' does not hold '%s'"
                            .formatted(role.getCode(), spec.permission())));
            if (!permission.isLimited()) {
                throw new BadRequestException("Permission '%s' is not limited".formatted(spec.permission()));
            }
            if (spec.maxAmount() != null && spec.maxAmount().signum() < 0) {
                throw new BadRequestException("Limits cannot be negative");
            }
            if (!resolved.add(new RoleLimit(permission, spec.currency(), spec.maxAmount()))) {
                throw new BadRequestException("Duplicate limit for %s in %s".formatted(spec.permission(), spec.currency()));
            }
        }
        return resolved;
    }

    /**
     * Holders of a role can assign everything reachable down its chain, so chains must be a
     * hierarchy: if the role were reachable from its own assignable roles, its holders could create
     * peers or superiors.
     */
    private static void requireNoCycle(Role role, Set<Role> assignable) {
        Set<Long> seen = new HashSet<>();
        Deque<Role> pending = new ArrayDeque<>(assignable);
        while (!pending.isEmpty()) {
            Role next = pending.pop();
            if (next.getId().equals(role.getId())) {
                throw new BadRequestException("'%s' would be able to assign itself or a superior: role chains must not loop"
                        .formatted(AclViews.RoleView.reference(role)));
            }
            if (seen.add(next.getId())) {
                pending.addAll(next.getAssignableRoles());
            }
        }
    }

    private static void requireNoPlatformOnly(Collection<Permission> permissions) {
        List<String> platformOnly = permissions.stream()
                .map(Permission::getCode)
                .filter(AccessGuard.PLATFORM_ONLY::contains)
                .sorted()
                .toList();
        if (!platformOnly.isEmpty()) {
            throw new BadRequestException("Tenant roles cannot carry platform-only permissions: " + platformOnly);
        }
    }

    private static String describe(List<LimitSpec> limits) {
        return limits == null ? "[]" : limits.stream().map(LimitSpec::toString).sorted().toList().toString();
    }

    private Application application(String code) {
        return applications.findByCode(code)
                .orElseThrow(() -> new NotFoundException("Application '%s' not found".formatted(code)));
    }

    private Role role(String applicationCode, String roleCode, String tenantCode) {
        Application application = application(applicationCode);
        return (tenantCode == null
                ? roles.findByApplicationAndCodeAndTenantIsNull(application, roleCode)
                : roles.findByApplicationAndCodeAndTenant(application, roleCode, tenants.tenant(tenantCode)))
                .orElseThrow(() -> new NotFoundException("Role '%s' not found in '%s'%s".formatted(roleCode,
                        applicationCode, tenantCode == null ? "" : " for '%s'".formatted(tenantCode))));
    }

    private boolean roleExists(String applicationCode, String roleCode, String tenantCode) {
        Application application = application(applicationCode);
        return tenantCode == null
                ? roles.existsByApplicationAndCodeAndTenantIsNull(application, roleCode)
                : roles.existsByApplicationAndCodeAndTenant(application, roleCode, tenants.tenant(tenantCode));
    }

    /** A target type usable in the tenant: its own, else shared ({@code tenant == null}: shared only). */
    private TargetType targetType(String code, Tenant tenant) {
        return (tenant == null ? java.util.Optional.<TargetType>empty() : targetTypes.findByCodeAndTenant(code, tenant))
                .or(() -> targetTypes.findByCodeAndTenantIsNull(code))
                .orElseThrow(() -> new NotFoundException("Target type '%s' not found".formatted(code)));
    }

    private Target target(String code) {
        return targets.findByCode(code)
                .orElseThrow(() -> new NotFoundException("Target '%s' not found".formatted(code)));
    }

    /** A requested limit; {@code maxAmount == null} means unlimited. */
    public record LimitSpec(String permission, String currency, BigDecimal maxAmount) {

        @Override
        public String toString() {
            return "%s %s %s".formatted(permission, currency, maxAmount == null ? "unlimited" : maxAmount.toPlainString());
        }
    }
}
