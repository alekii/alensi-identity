package io.alensi.identity.acl;

import java.math.BigDecimal;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;

import io.alensi.identity.web.NotFoundException;

/**
 * Answers permission questions for one user in one application.
 *
 * <p>Permission maps are shaped {@code targetType -> targetCode -> permissions}. Grants on all
 * targets appear under {@code "*" -> "*"}. Methods taking a {@link Scope} only report what lies
 * inside it; a wildcard grant seen through a narrower scope is reported on the scope's roots.
 */
public final class PermissionEvaluator {

    public static final String WILDCARD = "*";

    private final TargetTree tree;
    private final List<EffectiveGrant> grants;
    private final Set<String> limitedPermissions;

    public PermissionEvaluator(TargetTree tree, List<EffectiveGrant> grants) {
        this(tree, grants, Set.of());
    }

    public PermissionEvaluator(TargetTree tree, List<EffectiveGrant> grants, Set<String> limitedPermissions) {
        this.tree = tree;
        this.grants = List.copyOf(grants);
        this.limitedPermissions = Set.copyOf(limitedPermissions);
    }

    public boolean isLimited(String permission) {
        return limitedPermissions.contains(permission);
    }

    /**
     * The best limit per currency for the permission on the target, across every grant that covers
     * it. A currency missing from the result means no authority in that currency.
     */
    public List<Limit> limits(String permission, TargetNode target) {
        List<TargetNode> covering = tree.ancestorsOrSelf(target);
        Map<String, Limit> best = new TreeMap<>();
        grants.stream()
                .filter(grant -> grant.permissions().contains(permission))
                .filter(grant -> grant.isWildcard() || covering.contains(grant.target()))
                .flatMap(grant -> grant.limits().stream())
                .filter(limit -> limit.permission().equals(permission))
                .forEach(limit -> best.merge(limit.currency(), limit, Limit::max));
        return List.copyOf(best.values());
    }

    /** True if the user holds the permission on the target with a limit covering the amount. */
    public boolean hasPermission(String permission, TargetNode target, BigDecimal amount, String currency) {
        return hasPermission(permission, target) && limits(permission, target).stream()
                .anyMatch(limit -> limit.currency().equals(currency) && limit.allows(amount));
    }

    public Optional<TargetNode> findTarget(String code) {
        return tree.find(code);
    }

    public TargetNode requireTarget(String code) {
        return tree.find(code).orElseThrow(() -> new NotFoundException("Target '%s' not found".formatted(code)));
    }

    /** Where in the tree the user holds the permission. */
    public Scope scope(String permission) {
        boolean wildcard = false;
        Set<TargetNode> roots = new LinkedHashSet<>();
        for (EffectiveGrant grant : grants) {
            if (grant.permissions().contains(permission)) {
                if (grant.isWildcard()) {
                    wildcard = true;
                }
                else {
                    roots.add(grant.target());
                }
            }
        }
        return new Scope(wildcard, wildcard ? Set.of() : roots, tree);
    }

    /**
     * True if the user may assign the role on the target (or on all targets when {@code target} is
     * null): a grant carrying {@code managePermission} lists the role as assignable and covers the target.
     */
    public boolean canAssign(String managePermission, long roleId, TargetNode target) {
        return grants.stream()
                .filter(grant -> grant.permissions().contains(managePermission))
                .filter(grant -> grant.assignableRoleIds().contains(roleId))
                .anyMatch(grant -> grant.isWildcard()
                        || target != null && tree.ancestorsOrSelf(target).contains(grant.target()));
    }

    /** True if the user holds the permission on at least one target. */
    public boolean hasPermission(String permission) {
        return hasPermission(permission, Scope.ALL);
    }

    /** True if the user holds the permission on at least one target inside the scope. */
    public boolean hasPermission(String permission, Scope scope) {
        return grants.stream()
                .filter(grant -> grant.permissions().contains(permission))
                .anyMatch(grant -> grant.isWildcard() && scope.wildcard() || !within(grant, scope, false).isEmpty());
    }

    /** True if the user holds the permission on the target, directly, through an ancestor, or via a wildcard grant. */
    public boolean hasPermission(String permission, TargetNode target) {
        List<TargetNode> covering = tree.ancestorsOrSelf(target);
        return grants.stream()
                .filter(grant -> grant.permissions().contains(permission))
                .anyMatch(grant -> grant.isWildcard() || covering.contains(grant.target()));
    }

    public SortedMap<String, SortedMap<String, SortedSet<String>>> permissions(boolean compressed, String targetType) {
        return permissions(compressed, targetType, Scope.ALL);
    }

    /**
     * All permissions. Compressed returns grants where they were made; expanded also repeats them on
     * every descendant target.
     */
    public SortedMap<String, SortedMap<String, SortedSet<String>>> permissions(boolean compressed, String targetType,
            Scope scope) {
        var result = new TreeMap<String, SortedMap<String, SortedSet<String>>>();
        for (EffectiveGrant grant : grants) {
            if (grant.isWildcard() && scope.wildcard()) {
                add(result, WILDCARD, WILDCARD, grant.permissions());
                continue;
            }
            within(grant, scope, !compressed).stream()
                    .filter(node -> targetType == null || node.type().equals(targetType))
                    .forEach(node -> add(result, node.type(), node.code(), grant.permissions()));
        }
        return result;
    }

    /** The permissions that apply on one target, including inherited and wildcard grants. */
    public SortedMap<String, SortedMap<String, SortedSet<String>>> permissionsOn(TargetNode target) {
        List<TargetNode> covering = tree.ancestorsOrSelf(target);
        var result = new TreeMap<String, SortedMap<String, SortedSet<String>>>();
        grants.stream()
                .filter(grant -> grant.isWildcard() || covering.contains(grant.target()))
                .forEach(grant -> add(result, target.type(), target.code(), grant.permissions()));
        return result;
    }

    public List<String> targetsWith(String permission, boolean compressed) {
        return targetsWith(permission, compressed, Scope.ALL);
    }

    /** Codes of the targets on which the user holds the permission, or {@code ["*"]} if it is held everywhere. */
    public List<String> targetsWith(String permission, boolean compressed, Scope scope) {
        List<EffectiveGrant> matching = grants.stream()
                .filter(grant -> grant.permissions().contains(permission))
                .toList();
        if (scope.wildcard() && matching.stream().anyMatch(EffectiveGrant::isWildcard)) {
            return List.of(WILDCARD);
        }
        return matching.stream()
                .flatMap(grant -> within(grant, scope, !compressed).stream())
                .map(TargetNode::code)
                .distinct()
                .sorted()
                .toList();
    }

    public List<TargetNode> targets(String targetType) {
        return targets(targetType, Scope.ALL);
    }

    /** Targets the user has any grant on (expanded to descendants), optionally restricted to a type. */
    public List<TargetNode> targets(String targetType, Scope scope) {
        Set<TargetNode> result = new LinkedHashSet<>();
        for (EffectiveGrant grant : grants) {
            result.addAll(grant.isWildcard() && scope.wildcard() ? tree.all() : within(grant, scope, true));
        }
        return result.stream()
                .filter(node -> targetType == null || node.type().equals(targetType))
                .sorted(Comparator.comparing(TargetNode::code))
                .toList();
    }

    /**
     * The targets a non-wildcard view of the grant reports inside the scope. Unexpanded, a grant above
     * the scope is reported on the scope's roots beneath it.
     */
    private List<TargetNode> within(EffectiveGrant grant, Scope scope, boolean expand) {
        List<TargetNode> starts = grant.isWildcard()
                ? List.copyOf(scope.roots())
                : scope.covers(grant.target())
                        ? List.of(grant.target())
                        : scope.roots().stream().filter(root -> tree.ancestorsOrSelf(root).contains(grant.target())).toList();
        if (!expand) {
            return starts;
        }
        return starts.stream().flatMap(start -> tree.descendantsOrSelf(start).stream()).distinct().toList();
    }

    private static void add(Map<String, SortedMap<String, SortedSet<String>>> result, String type, String code,
            Set<String> permissions) {
        result.computeIfAbsent(type, key -> new TreeMap<>())
                .computeIfAbsent(code, key -> new TreeSet<>())
                .addAll(permissions);
    }
}
