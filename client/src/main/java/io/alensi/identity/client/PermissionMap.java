package io.alensi.identity.client;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * A user's permissions in one application and tenant, as returned (expanded to descendant targets)
 * by alensi-identity: {@code targetType -> targetCode -> permissions}, with grants on all targets
 * under {@code "*" -> "*"}. Expansion means checks need no knowledge of the target hierarchy.
 */
public record PermissionMap(Map<String, Map<String, Set<String>>> byType) {

    static final String WILDCARD = "*";

    public PermissionMap {
        byType = byType == null ? Map.of() : Map.copyOf(byType);
    }

    public boolean allows(String permission, String target) {
        return everywhere(permission) || byType.values().stream()
                .anyMatch(byCode -> byCode.getOrDefault(target, Set.of()).contains(permission));
    }

    public boolean allowsAnywhere(String permission) {
        return byType.values().stream()
                .flatMap(byCode -> byCode.values().stream())
                .anyMatch(permissions -> permissions.contains(permission));
    }

    public TargetScope scope(String permission) {
        if (everywhere(permission)) {
            return TargetScope.everywhere();
        }
        Set<String> targets = new HashSet<>();
        byType.forEach((type, byCode) -> byCode.forEach((code, permissions) -> {
            if (permissions.contains(permission)) {
                targets.add(code);
            }
        }));
        return new TargetScope(false, targets);
    }

    private boolean everywhere(String permission) {
        return byType.getOrDefault(WILDCARD, Map.of()).getOrDefault(WILDCARD, Set.of()).contains(permission);
    }
}
