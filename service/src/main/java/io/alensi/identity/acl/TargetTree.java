package io.alensi.identity.acl;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** In-memory index of the target hierarchy. */
public final class TargetTree {

    private final Map<Long, TargetNode> byId = new HashMap<>();
    private final Map<String, TargetNode> byCode = new HashMap<>();
    private final Map<Long, List<TargetNode>> children = new HashMap<>();

    public TargetTree(Collection<TargetNode> nodes) {
        for (TargetNode node : nodes) {
            byId.put(node.id(), node);
            byCode.put(node.code(), node);
            if (node.parentId() != null) {
                children.computeIfAbsent(node.parentId(), id -> new ArrayList<>()).add(node);
            }
        }
    }

    public Optional<TargetNode> find(String code) {
        return Optional.ofNullable(byCode.get(code));
    }

    public Collection<TargetNode> all() {
        return byId.values();
    }

    /** The node followed by its parent, grandparent, ... up to the root. */
    public List<TargetNode> ancestorsOrSelf(TargetNode node) {
        List<TargetNode> path = new ArrayList<>();
        for (TargetNode current = node; current != null && !path.contains(current);
                current = current.parentId() == null ? null : byId.get(current.parentId())) {
            path.add(current);
        }
        return path;
    }

    /** The top-level ancestor of the node (its company, in alensi-insure). */
    public TargetNode root(TargetNode node) {
        List<TargetNode> path = ancestorsOrSelf(node);
        return path.get(path.size() - 1);
    }

    /** The node and every node below it, breadth first. */
    public List<TargetNode> descendantsOrSelf(TargetNode node) {
        List<TargetNode> result = new ArrayList<>();
        var queue = new ArrayDeque<TargetNode>();
        queue.add(node);
        while (!queue.isEmpty()) {
            TargetNode current = queue.poll();
            if (!result.contains(current)) {
                result.add(current);
                queue.addAll(children.getOrDefault(current.id(), List.of()));
            }
        }
        return result;
    }
}
