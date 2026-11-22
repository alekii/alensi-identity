package io.alensi.identity.acl;

import java.time.Instant;
import java.util.Comparator;
import java.util.List;
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

    public record PermissionView(String code, String description, boolean limited) {

        static PermissionView of(Permission permission) {
            return new PermissionView(permission.getCode(), permission.getDescription(), permission.isLimited());
        }
    }

    /**
     * {@code tenant} owns the role ({@code null} for shared roles). {@code assignableRoles} are
     * {@code application/role} references, suffixed {@code @tenant} for tenant-owned roles.
     */
    public record RoleView(String code, String name, String tenant, SortedSet<String> permissions,
            SortedSet<String> assignableRoles, List<Limit> limits) {

        static RoleView of(Role role) {
            var codes = new TreeSet<String>();
            role.getPermissions().forEach(permission -> codes.add(permission.getCode()));
            var assignable = new TreeSet<String>();
            role.getAssignableRoles().forEach(r -> assignable.add(reference(r)));
            List<Limit> limits = role.getLimits().stream()
                    .map(limit -> new Limit(limit.getPermission().getCode(), limit.getCurrency(), limit.getMaxAmount()))
                    .sorted(Comparator.comparing(Limit::permission).thenComparing(Limit::currency))
                    .toList();
            return new RoleView(role.getCode(), role.getName(), tenantCode(role), codes, assignable, limits);
        }

        static String reference(Role role) {
            String ref = role.getApplication().getCode() + "/" + role.getCode();
            return role.isShared() ? ref : ref + "@" + role.getTenant().getCode();
        }

        static String tenantCode(Role role) {
            return role.isShared() ? null : role.getTenant().getCode();
        }
    }

    /** {@code tenant} is null for types shared by all tenants. */
    public record TargetTypeView(String code, String name, String parent, String tenant) {

        static TargetTypeView of(TargetType type) {
            return new TargetTypeView(type.getCode(), type.getName(),
                    type.getParent() == null ? null : type.getParent().getCode(),
                    type.getTenant() == null ? null : type.getTenant().getCode());
        }
    }

    public record TargetView(String code, String name, String type, String parent, String tenant) {

        static TargetView of(Target target) {
            return new TargetView(target.getCode(), target.getName(), target.getType().getCode(),
                    target.getParent() == null ? null : target.getParent().getCode(), target.getTenant().getCode());
        }
    }

    /** {@code tenant} is the grant's tenant (null for platform grants on {@code *}). */
    public record GrantView(Long id, String tenant, String application, String role, String target,
            UUID grantedBy, Instant createdAt) {

        static GrantView of(RoleGrant grant) {
            return new GrantView(grant.getId(), grant.getTenant() == null ? null : grant.getTenant().getCode(),
                    grant.getRole().getApplication().getCode(), grant.getRole().getCode(),
                    grant.isWildcard() ? PermissionEvaluator.WILDCARD : grant.getTarget().getCode(),
                    grant.getGrantedBy(), grant.getCreatedAt());
        }
    }
}
