package io.alensi.identity.acl;

import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import io.alensi.identity.tenant.TenantMember;
import io.alensi.identity.tenant.TenantMemberRepository;
import io.alensi.identity.user.UserAccount;
import io.alensi.identity.web.NotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
public class PermissionService {

    private final ApplicationRepository applications;
    private final PermissionRepository permissions;
    private final RoleGrantRepository grants;
    private final TargetRepository targets;
    private final TenantMemberRepository members;

    PermissionService(ApplicationRepository applications, PermissionRepository permissions,
            RoleGrantRepository grants, TargetRepository targets, TenantMemberRepository members) {
        this.applications = applications;
        this.permissions = permissions;
        this.grants = grants;
        this.targets = targets;
        this.members = members;
    }

    /** The user's permissions across all tenants they are an active member of. */
    public PermissionEvaluator evaluatorFor(UserAccount user, String applicationCode) {
        return evaluatorFor(user, applicationCode, null);
    }

    /**
     * The user's permissions in one tenant ({@code tenantId}), or across all their tenants when
     * {@code null}. Platform (wildcard) grants always apply. Grants in tenants where the membership
     * is suspended or expired are ignored, as is everything for a suspended account.
     */
    public PermissionEvaluator evaluatorFor(UserAccount user, String applicationCode, Long tenantId) {
        if (!applications.existsByCode(applicationCode)) {
            throw new NotFoundException("Application '%s' not found".formatted(applicationCode));
        }
        List<EffectiveGrant> effective = effective(user, grants.findForUserInApplication(user, applicationCode), tenantId)
                .map(grant -> new EffectiveGrant(target(grant), permissionCodes(grant.getRole()),
                        assignableRoleIds(grant.getRole()), limits(grant.getRole())))
                .toList();
        return new PermissionEvaluator(targetTree(), effective, permissions.findLimitedCodes(applicationCode));
    }

    /**
     * Who and where the user manages, across every application: a role in any application can carry
     * assignable roles (e.g. alensi-insure's branch-manager assigning sales-manager). Carries no
     * permissions, so a permission in one application can never satisfy a check in another.
     */
    public PermissionEvaluator managementEvaluatorFor(UserAccount user) {
        List<EffectiveGrant> effective = effective(user, grants.findForUser(user), null)
                .filter(grant -> !grant.getRole().getAssignableRoles().isEmpty())
                .map(grant -> new EffectiveGrant(target(grant), Set.of(), assignableRoleIds(grant.getRole()), List.of()))
                .toList();
        return new PermissionEvaluator(targetTree(), effective);
    }

    /** Grants that are in force: account active, and the membership of the grant's tenant active. */
    private Stream<RoleGrant> effective(UserAccount user, List<RoleGrant> candidates, Long tenantId) {
        Instant now = Instant.now();
        if (!user.isActiveAt(now)) {
            return Stream.empty();
        }
        Set<Long> activeTenants = members.findByUser(user).stream()
                .filter(member -> member.isActiveAt(now))
                .map(member -> member.getTenant().getId())
                .filter(id -> tenantId == null || id.equals(tenantId))
                .collect(Collectors.toSet());
        return candidates.stream()
                .filter(grant -> grant.isWildcard() || activeTenants.contains(grant.getTenant().getId()));
    }

    private static TargetNode target(RoleGrant grant) {
        return grant.isWildcard() ? null : TargetNode.of(grant.getTarget());
    }

    /**
     * Every role reachable down the role's chain: a manager may assign anything their subordinates
     * may. The role itself is never included, so a cycle in the configuration cannot let anyone
     * create peers.
     */
    private static Set<Long> assignableRoleIds(Role role) {
        Set<Long> reachable = new HashSet<>();
        Deque<Role> pending = new ArrayDeque<>(role.getAssignableRoles());
        while (!pending.isEmpty()) {
            Role next = pending.pop();
            if (!next.getId().equals(role.getId()) && reachable.add(next.getId())) {
                pending.addAll(next.getAssignableRoles());
            }
        }
        return reachable;
    }

    /** The whole target hierarchy, for callers that need to place targets relative to each other. */
    public TargetTree targetTree() {
        // Loaded per call; targets are low-volume reference data. Cache here if that changes.
        return new TargetTree(targets.findAllWithTypeAndParent().stream().map(TargetNode::of).toList());
    }

    /** Tenants in which the user's membership is currently active. */
    public List<TenantMember> activeMemberships(UserAccount user) {
        Instant now = Instant.now();
        return members.findByUser(user).stream().filter(member -> member.isActiveAt(now)).toList();
    }

    private static Set<String> permissionCodes(Role role) {
        return role.getPermissions().stream().map(Permission::getCode).collect(Collectors.toSet());
    }

    private static List<Limit> limits(Role role) {
        return role.getLimits().stream()
                .map(limit -> new Limit(limit.getPermission().getCode(), limit.getCurrency(), limit.getMaxAmount()))
                .toList();
    }
}
