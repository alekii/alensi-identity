package io.alensi.identity.acl;

import java.util.Set;

/**
 * The part of the target tree a caller holds some permission on: everything ({@code wildcard}) or the
 * subtrees under {@code roots}. Used to clip what a caller may see of, or do to, other users.
 */
public record Scope(boolean wildcard, Set<TargetNode> roots, TargetTree tree) {

    /** Unrestricted, e.g. a user looking at their own permissions. */
    public static final Scope ALL = new Scope(true, Set.of(), null);

    public Scope {
        roots = Set.copyOf(roots);
    }

    /** Everything covered by either scope. */
    public Scope union(Scope other) {
        if (wildcard || other.wildcard) {
            return new Scope(true, Set.of(), tree != null ? tree : other.tree);
        }
        var combined = new java.util.LinkedHashSet<>(roots);
        combined.addAll(other.roots);
        return new Scope(false, combined, tree);
    }

    public boolean isEmpty() {
        return !wildcard && roots.isEmpty();
    }

    /** True if the node lies inside the scope. */
    public boolean covers(TargetNode node) {
        return wildcard || tree.ancestorsOrSelf(node).stream().anyMatch(roots::contains);
    }

    /** True if the target code lies inside the scope; {@code "*"} is only covered by a wildcard scope. */
    public boolean covers(String code) {
        if (wildcard) {
            return true;
        }
        return !PermissionEvaluator.WILDCARD.equals(code) && tree.find(code).map(this::covers).orElse(false);
    }
}
