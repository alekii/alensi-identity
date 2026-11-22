package io.alensi.identity.acl;

/** Immutable view of a {@link Target} used for permission evaluation. */
public record TargetNode(long id, String code, String name, String type, Long parentId) {

    static TargetNode of(Target target) {
        Target parent = target.getParent();
        return new TargetNode(target.getId(), target.getCode(), target.getName(), target.getType().getCode(),
                parent == null ? null : parent.getId());
    }
}
