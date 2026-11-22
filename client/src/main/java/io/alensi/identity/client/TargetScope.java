package io.alensi.identity.client;

import java.util.Set;

/**
 * Where a user holds a permission: everywhere ({@link #all()}) or on these target codes, already
 * expanded to descendants. Use it to filter queries:
 *
 * <pre>{@code
 * TargetScope scope = access.scope("claims.view");
 * return scope.all() ? claims.findAll(tenant) : claims.findByBranchIn(tenant, scope.targets());
 * }</pre>
 */
public record TargetScope(boolean all, Set<String> targets) {

    public TargetScope {
        targets = Set.copyOf(targets);
    }

    public static TargetScope everywhere() {
        return new TargetScope(true, Set.of());
    }

    public static TargetScope nowhere() {
        return new TargetScope(false, Set.of());
    }

    public boolean includes(String target) {
        return all || targets.contains(target);
    }

    public boolean isEmpty() {
        return !all && targets.isEmpty();
    }
}
