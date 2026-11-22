package io.alensi.identity.user;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import io.alensi.identity.acl.PermissionEvaluator;
import io.alensi.identity.acl.PermissionService;
import io.alensi.identity.acl.Role;
import io.alensi.identity.acl.RoleGrant;
import io.alensi.identity.acl.RoleGrantRepository;
import io.alensi.identity.acl.Scope;
import io.alensi.identity.acl.TargetNode;
import io.alensi.identity.acl.TargetRepository;
import io.alensi.identity.tenant.Tenant;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Authorizes calls to this service's own API. Every check is scoped to the target tree, and every
 * target belongs to exactly one tenant, so scope also enforces tenant isolation: holding something
 * on a Jubilee branch never authorizes acting on Madison. Only grants on all targets ({@code *})
 * authorize platform-wide actions.
 */
@Component
@Transactional(readOnly = true)
public class AccessGuard {

    public static final String APPLICATION = "alensi-identity";
    public static final String PLATFORM_MANAGE = "identity.platform.manage";
    public static final String USERS_MANAGE = "identity.users.manage";
    public static final String TARGETS_MANAGE = "identity.targets.manage";
    public static final String ROLES_MANAGE = "identity.roles.manage";
    public static final String USERS_READ = "identity.users.read";
    public static final String PERMISSIONS_READ = "identity.permissions.read";
    public static final String AUDIT_READ = "identity.audit.read";

    /** Permissions that only make sense on all targets; tenant-owned roles may never carry them. */
    public static final Set<String> PLATFORM_ONLY = Set.of(PLATFORM_MANAGE, AUDIT_READ);

    private final PermissionService permissions;
    private final RoleGrantRepository grants;
    private final TargetRepository targets;

    AccessGuard(PermissionService permissions, RoleGrantRepository grants, TargetRepository targets) {
        this.permissions = permissions;
        this.grants = grants;
        this.targets = targets;
    }

    /** Catalog changes, tenant creation and anything else that affects every tenant. */
    public void requirePlatform(UserAccount caller) {
        requireGlobal(caller, PLATFORM_MANAGE);
    }

    /** The permission must be held on all targets. */
    public void requireGlobal(UserAccount caller, String permission) {
        if (!evaluator(caller).scope(permission).wildcard()) {
            throw new AccessDeniedException("Requires '%s' on all targets".formatted(permission));
        }
    }

    public boolean isPlatformAdmin(UserAccount caller) {
        return isPlatformAdmin(evaluator(caller));
    }

    /** Fails fast when the caller can neither read access via the permission nor manage anyone. */
    public void requireCanSeeOthers(UserAccount caller, String permission) {
        if (evaluator(caller).scope(permission).union(management(caller).managementScope()).isEmpty()) {
            throw new AccessDeniedException("Missing permission '%s'".formatted(permission));
        }
    }

    /**
     * Tenant administration (members, tenant audit trail): {@code identity.users.manage} on the
     * tenant's root target.
     */
    public void requireTenantAdmin(UserAccount caller, Tenant tenant) {
        requireOnRoot(caller, tenant, USERS_MANAGE);
    }

    /**
     * Tenant configuration (its own roles, limits and target types): {@code identity.roles.manage}
     * on the tenant's root target. Shared configuration ({@code tenant == null}) is platform-only.
     */
    public void requireTenantConfiguration(UserAccount caller, Tenant tenant) {
        if (tenant == null) {
            requirePlatform(caller);
            return;
        }
        requireOnRoot(caller, tenant, ROLES_MANAGE);
    }

    /** Creating a target under {@code parentCode}. Tenant roots are created with the tenant. */
    public void requireTargetManagement(UserAccount caller, String parentCode) {
        PermissionEvaluator evaluator = evaluator(caller);
        if (isPlatformAdmin(evaluator)) {
            return;
        }
        if (!evaluator.scope(TARGETS_MANAGE).covers(evaluator.requireTarget(parentCode))) {
            throw new AccessDeniedException("Target '%s' is outside your scope".formatted(parentCode));
        }
    }

    /**
     * Granting or revoking {@code role} for {@code subject} on {@code targetCode} ({@code null} = all
     * targets). Allowed for platform admins; for anyone whose grant covering the target lists the
     * role as assignable; and for tenant configurators, for their own tenant's roles.
     */
    public void requireCanAssign(UserAccount caller, UserAccount subject, Role role, String targetCode) {
        requireNotSelf(caller, subject);
        requireCanAssign(caller, role, targetCode);
    }

    /** As above, before the grantee exists (e.g. checking an onboarding request before creating the account). */
    public void requireCanAssign(UserAccount caller, Role role, String targetCode) {
        PermissionEvaluator evaluator = evaluator(caller);
        TargetNode target = targetCode == null ? null : evaluator.requireTarget(targetCode);
        if (!canAssign(evaluator, management(caller), role, target)) {
            throw new AccessDeniedException("You may not assign or revoke '%s' on %s".formatted(role.getCode(),
                    targetCode == null ? "all targets" : "'" + targetCode + "'"));
        }
    }

    /**
     * Changing someone's membership of a tenant (suspension, expiry). Allowed for tenant admins, and
     * for managers who could revoke every grant the subject holds in that tenant, so a team lead can
     * suspend their agent but not someone who also works elsewhere in the company.
     */
    public void requireMembershipManagement(UserAccount caller, UserAccount subject, Tenant tenant) {
        requireNotSelf(caller, subject);
        PermissionEvaluator evaluator = evaluator(caller);
        if (isPlatformAdmin(evaluator) || covers(evaluator, USERS_MANAGE, root(evaluator, tenant))) {
            return;
        }
        List<RoleGrant> inTenant = grants.findForUser(subject).stream()
                .filter(grant -> !grant.isWildcard() && grant.getTenant().getId().equals(tenant.getId()))
                .toList();
        if (inTenant.isEmpty()) {
            throw new AccessDeniedException("Only tenant administrators can manage members without grants");
        }
        PermissionEvaluator management = management(caller);
        for (RoleGrant grant : inTenant) {
            if (!canAssign(evaluator, management, grant.getRole(), evaluator.requireTarget(grant.getTarget().getCode()))) {
                throw new AccessDeniedException("'%s' holds access outside your scope".formatted(subject.getUsername()));
            }
        }
    }

    /**
     * What part of {@code subject}'s access the caller may see. Users see all of their own. Others
     * need the permission, or a management role, over a target where the subject holds a grant, i.e.
     * the subject works inside the caller's scope; what they see is clipped to that scope.
     */
    public Scope readScope(UserAccount caller, UserAccount subject, String permission) {
        if (caller.getId().equals(subject.getId())) {
            return Scope.ALL;
        }
        PermissionEvaluator evaluator = evaluator(caller);
        Scope scope = evaluator.scope(permission).union(management(caller).managementScope());
        if (scope.wildcard()) {
            return scope;
        }
        // Only people with a grant inside the caller's scope: those they oversee, never those above them.
        boolean oversees = grants.findForUser(subject).stream()
                .anyMatch(grant -> !grant.isWildcard()
                        && scope.covers(evaluator.requireTarget(grant.getTarget().getCode())));
        if (!oversees) {
            throw new AccessDeniedException("'%s' is outside your scope".formatted(subject.getUsername()));
        }
        return scope;
    }

    /** Codes of the tenants the caller works in, or {@code null} if they may see all tenants. */
    public Set<String> visibleTenants(UserAccount caller) {
        if (isPlatformAdmin(caller)) {
            return null;
        }
        return permissions.activeMemberships(caller).stream()
                .map(member -> member.getTenant().getCode())
                .collect(Collectors.toSet());
    }

    private void requireOnRoot(UserAccount caller, Tenant tenant, String permission) {
        PermissionEvaluator evaluator = evaluator(caller);
        if (!isPlatformAdmin(evaluator) && !covers(evaluator, permission, root(evaluator, tenant))) {
            throw new AccessDeniedException("Requires '%s' on tenant '%s'".formatted(permission, tenant.getCode()));
        }
    }

    /**
     * {@code evaluator} holds the caller's alensi-identity permissions; {@code management} their
     * assignable roles across all applications.
     */
    private static boolean canAssign(PermissionEvaluator evaluator, PermissionEvaluator management, Role role,
            TargetNode target) {
        if (isPlatformAdmin(evaluator) || management.canAssign(role.getId(), target)) {
            return true;
        }
        return !role.isShared() && target != null && covers(evaluator, ROLES_MANAGE, target);
    }

    private TargetNode root(PermissionEvaluator evaluator, Tenant tenant) {
        String rootCode = targets.findByTenantAndParentIsNull(tenant).orElseThrow().getCode();
        return evaluator.requireTarget(rootCode);
    }

    private static boolean covers(PermissionEvaluator evaluator, String permission, TargetNode target) {
        return evaluator.scope(permission).covers(target);
    }

    private static boolean isPlatformAdmin(PermissionEvaluator evaluator) {
        return evaluator.scope(PLATFORM_MANAGE).wildcard();
    }

    private static void requireNotSelf(UserAccount caller, UserAccount subject) {
        if (caller.getId().equals(subject.getId())) {
            throw new AccessDeniedException("You cannot change your own access");
        }
    }

    private PermissionEvaluator evaluator(UserAccount caller) {
        return permissions.evaluatorFor(caller, APPLICATION);
    }

    private PermissionEvaluator management(UserAccount caller) {
        return permissions.managementEvaluatorFor(caller);
    }
}
