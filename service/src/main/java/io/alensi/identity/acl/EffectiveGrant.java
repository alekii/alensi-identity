package io.alensi.identity.acl;

import java.util.List;
import java.util.Set;

/**
 * The permissions a user holds on a target (and its descendants), the roles they may assign there,
 * and the limits on limited permissions. A {@code null} target means all targets.
 */
public record EffectiveGrant(TargetNode target, Set<String> permissions, Set<Long> assignableRoleIds,
        List<Limit> limits) {

    public EffectiveGrant {
        permissions = Set.copyOf(permissions);
        assignableRoleIds = Set.copyOf(assignableRoleIds);
        limits = List.copyOf(limits);
    }

    public EffectiveGrant(TargetNode target, Set<String> permissions) {
        this(target, permissions, Set.of(), List.of());
    }

    public boolean isWildcard() {
        return target == null;
    }
}
