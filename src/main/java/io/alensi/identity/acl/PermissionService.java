package io.alensi.identity.acl;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

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

    PermissionService(ApplicationRepository applications, PermissionRepository permissions,
            RoleGrantRepository grants, TargetRepository targets) {
        this.applications = applications;
        this.permissions = permissions;
        this.grants = grants;
        this.targets = targets;
    }

    public PermissionEvaluator evaluatorFor(UserAccount user, String applicationCode) {
        if (!applications.existsByCode(applicationCode)) {
            throw new NotFoundException("Application '%s' not found".formatted(applicationCode));
        }
        Set<String> limited = permissions.findLimitedCodes(applicationCode);
        if (!user.isActiveAt(Instant.now())) {
            return new PermissionEvaluator(targetTree(), List.of(), limited);
        }
        List<EffectiveGrant> effective = grants.findForUserInApplication(user, applicationCode).stream()
                .map(grant -> new EffectiveGrant(
                        grant.isWildcard() ? null : TargetNode.of(grant.getTarget()),
                        permissionCodes(grant.getRole()),
                        grant.getRole().getAssignableRoles().stream().map(Role::getId).collect(Collectors.toSet()),
                        limits(grant.getRole())))
                .toList();
        return new PermissionEvaluator(targetTree(), effective, limited);
    }

    /** The whole target hierarchy, for callers that need to place targets relative to each other. */
    public TargetTree targetTree() {
        // Loaded per call; targets are low-volume reference data. Cache here if that changes.
        return new TargetTree(targets.findAllWithTypeAndParent().stream().map(TargetNode::of).toList());
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
