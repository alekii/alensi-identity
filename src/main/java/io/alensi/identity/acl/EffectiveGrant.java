package io.alensi.identity.acl;

import java.util.Set;

/**
 * The permissions a user holds on a target (and its descendants), and the roles they may assign
 * there. A {@code null} target means all targets.
 */
public record EffectiveGrant(TargetNode target, Set<String> permissions, Set<Long> assignableRoleIds) {

    public EffectiveGrant {
        permissions = Set.copyOf(permissions);
        assignableRoleIds = Set.copyOf(assignableRoleIds);
    }

    public EffectiveGrant(TargetNode target, Set<String> permissions) {
        this(target, permissions, Set.of());
    }

    public boolean isWildcard() {
        return target == null;
    }
}
