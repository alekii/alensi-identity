package io.alensi.identity.user;

import java.util.HashSet;
import java.util.Set;

import io.alensi.identity.acl.PermissionEvaluator;
import io.alensi.identity.acl.PermissionService;
import io.alensi.identity.acl.Role;
import io.alensi.identity.acl.RoleGrant;
import io.alensi.identity.acl.RoleGrantRepository;
import io.alensi.identity.acl.Scope;
import io.alensi.identity.acl.TargetNode;
import io.alensi.identity.acl.TargetTree;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Authorizes calls to this service's own API using the {@code alensi-identity} application's
 * permissions. Every check is scoped: holding a permission on a branch never authorizes acting on
 * another branch, and only grants on all targets ({@code *}) authorize platform-wide actions.
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

    /** Permissions that only make sense on all targets; company-owned roles may never carry them. */
    public static final Set<String> PLATFORM_ONLY = Set.of(PLATFORM_MANAGE, AUDIT_READ);

    private final PermissionService permissions;
    private final RoleGrantRepository grants;

    AccessGuard(PermissionService permissions, RoleGrantRepository grants) {
        this.permissions = permissions;
        this.grants = grants;
    }

    /** Catalog changes and anything else that affects every company. */
    public void requirePlatform(UserAccount caller) {
        requireGlobal(caller, PLATFORM_MANAGE);
    }

    /** The permission must be held on all targets. */
    public void requireGlobal(UserAccount caller, String permission) {
        if (!evaluator(caller).scope(permission).wildcard()) {
            throw new AccessDeniedException("Requires '%s' on all targets".formatted(permission));
        }
    }

    /** Fails fast when the caller holds the permission nowhere, before any user lookup. */
    public void requireAnywhere(UserAccount caller, String permission) {
        if (evaluator(caller).scope(permission).isEmpty()) {
            throw new AccessDeniedException("Missing permission '%s'".formatted(permission));
        }
    }

    /** Creating a target under {@code parentCode}; top-level targets (companies) are platform-only. */
    public void requireTargetManagement(UserAccount caller, String parentCode) {
        PermissionEvaluator evaluator = evaluator(caller);
        if (isPlatformAdmin(evaluator)) {
            return;
        }
        if (parentCode == null) {
            throw new AccessDeniedException("Only platform administrators can create top-level targets");
        }
        if (!evaluator.scope(TARGETS_MANAGE).covers(evaluator.requireTarget(parentCode))) {
            throw new AccessDeniedException("Target '%s' is outside your scope".formatted(parentCode));
        }
    }

    /**
     * Creating or configuring a role owned by {@code ownerCode} (a company); platform-wide roles
     * ({@code ownerCode == null}) are platform-only.
     */
    public void requireRoleManagement(UserAccount caller, String ownerCode) {
        PermissionEvaluator evaluator = evaluator(caller);
        if (isPlatformAdmin(evaluator)) {
            return;
        }
        if (ownerCode == null) {
            throw new AccessDeniedException("Only platform administrators can manage platform-wide roles");
        }
        if (!evaluator.scope(ROLES_MANAGE).covers(evaluator.requireTarget(ownerCode))) {
            throw new AccessDeniedException("Roles of '%s' are outside your scope".formatted(ownerCode));
        }
    }

    /**
     * The companies (top-level targets) whose private configuration the caller may see, or
     * {@code null} for all of them.
     */
    public Set<String> visibleCompanies(UserAccount caller) {
        TargetTree tree = permissions.targetTree();
        Set<String> companies = new HashSet<>();
        for (RoleGrant grant : grants.findForUser(caller)) {
            if (grant.isWildcard()) {
                return null;
            }
            tree.find(grant.getTarget().getCode()).ifPresent(node -> companies.add(tree.root(node).code()));
        }
        return companies;
    }

    /**
     * Granting or revoking {@code roleId} for {@code subject} on {@code targetCode} ({@code null} = all
     * targets). The role must be assignable by one of the caller's admin grants covering the target.
     */
    public void requireCanAssign(UserAccount caller, UserAccount subject, Role role, String targetCode) {
        requireNotSelf(caller, subject);
        PermissionEvaluator evaluator = evaluator(caller);
        TargetNode target = targetCode == null ? null : evaluator.requireTarget(targetCode);
        if (!canAssign(evaluator, role, target)) {
            throw new AccessDeniedException("You may not assign or revoke this role on %s"
                    .formatted(targetCode == null ? "all targets" : "'" + targetCode + "'"));
        }
    }

    /**
     * Account-wide changes (suspension, expiry). Allowed only if the caller could revoke every grant
     * the subject holds, so a branch admin cannot lock out someone who also works elsewhere.
     */
    public void requireAccountManagement(UserAccount caller, UserAccount subject) {
        requireNotSelf(caller, subject);
        PermissionEvaluator evaluator = evaluator(caller);
        if (isPlatformAdmin(evaluator)) {
            return;
        }
        var subjectGrants = grants.findForUser(subject);
        if (subjectGrants.isEmpty()) {
            throw new AccessDeniedException("Only platform administrators can manage accounts without grants");
        }
        for (RoleGrant grant : subjectGrants) {
            TargetNode target = grant.isWildcard() ? null : evaluator.requireTarget(grant.getTarget().getCode());
            if (!canAssign(evaluator, grant.getRole(), target)) {
                throw new AccessDeniedException("'%s' holds access outside your scope".formatted(subject.getUsername()));
            }
        }
    }

    /**
     * What part of {@code subject}'s access the caller may see. Users see all of their own; others
     * need the permission on a part of the tree where the subject holds some grant.
     */
    public Scope readScope(UserAccount caller, UserAccount subject, String permission) {
        if (caller.getId().equals(subject.getId())) {
            return Scope.ALL;
        }
        PermissionEvaluator evaluator = evaluator(caller);
        Scope scope = evaluator.scope(permission);
        if (scope.wildcard()) {
            return scope;
        }
        boolean overlaps = grants.findForUser(subject).stream()
                .anyMatch(grant -> scope.overlaps(grant.isWildcard() ? null
                        : evaluator.requireTarget(grant.getTarget().getCode())));
        if (!overlaps) {
            throw new AccessDeniedException("'%s' is outside your scope".formatted(subject.getUsername()));
        }
        return scope;
    }

    /**
     * Platform admins assign anything. Others need the role on the assignable list of an admin grant
     * covering the target; holders of {@code identity.roles.manage} may also assign their company's own roles.
     */
    private boolean canAssign(PermissionEvaluator evaluator, Role role, TargetNode target) {
        if (isPlatformAdmin(evaluator) || evaluator.canAssign(USERS_MANAGE, role.getId(), target)) {
            return true;
        }
        return !role.isPlatformWide() && target != null && evaluator.scope(ROLES_MANAGE).covers(target);
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
}
