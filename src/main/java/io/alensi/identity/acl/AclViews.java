package io.alensi.identity.acl;

import java.time.Instant;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.UUID;

/** API representations of the ACL catalog. Built inside a transaction from managed entities. */
public final class AclViews {

    private AclViews() {
    }

    public record ApplicationView(String code, String name, String description) {

        static ApplicationView of(Application application) {
            return new ApplicationView(application.getCode(), application.getName(), application.getDescription());
        }
    }

    public record PermissionView(String code, String description) {

        static PermissionView of(Permission permission) {
            return new PermissionView(permission.getCode(), permission.getDescription());
        }
    }

    /** {@code assignableRoles} are {@code application/role} references. */
    public record RoleView(String code, String name, SortedSet<String> permissions, SortedSet<String> assignableRoles) {

        static RoleView of(Role role) {
            var codes = new TreeSet<String>();
            role.getPermissions().forEach(permission -> codes.add(permission.getCode()));
            var assignable = new TreeSet<String>();
            role.getAssignableRoles().forEach(r -> assignable.add(r.getApplication().getCode() + "/" + r.getCode()));
            return new RoleView(role.getCode(), role.getName(), codes, assignable);
        }
    }

    public record TargetTypeView(String code, String name, String parent) {

        static TargetTypeView of(TargetType type) {
            return new TargetTypeView(type.getCode(), type.getName(),
                    type.getParent() == null ? null : type.getParent().getCode());
        }
    }

    public record TargetView(String code, String name, String type, String parent) {

        static TargetView of(Target target) {
            return new TargetView(target.getCode(), target.getName(), target.getType().getCode(),
                    target.getParent() == null ? null : target.getParent().getCode());
        }
    }

    public record GrantView(Long id, String application, String role, String target, UUID grantedBy,
            Instant createdAt) {

        static GrantView of(RoleGrant grant) {
            return new GrantView(grant.getId(), grant.getRole().getApplication().getCode(), grant.getRole().getCode(),
                    grant.isWildcard() ? PermissionEvaluator.WILDCARD : grant.getTarget().getCode(),
                    grant.getGrantedBy(), grant.getCreatedAt());
        }
    }
}
