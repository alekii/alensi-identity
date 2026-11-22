package io.alensi.identity.acl;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;

import io.alensi.identity.audit.AuditLog;
import io.alensi.identity.user.UserAccount;
import io.alensi.identity.web.BadRequestException;
import io.alensi.identity.web.ConflictException;
import io.alensi.identity.web.NotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Applies an application's catalog (its permissions, shared roles, limits, management chains and
 * the shared target types it relies on) from a manifest, idempotently. Platform-only.
 *
 * <p>Additive: items missing from the manifest are left alone, because removing a permission or
 * role in use is a deliberate migration. Roles named in the manifest are brought exactly in line
 * with it (name, permissions, assignable roles, limits). Changing an existing target type's parent
 * or a permission's {@code limited} flag is refused for the same reason.
 */
@Service
@Transactional
public class CatalogService {

    private final ApplicationRepository applications;
    private final PermissionRepository permissions;
    private final RoleRepository roles;
    private final TargetTypeRepository targetTypes;
    private final AccessGuard access;
    private final AuditLog audit;

    CatalogService(ApplicationRepository applications, PermissionRepository permissions, RoleRepository roles,
            TargetTypeRepository targetTypes, AccessGuard access, AuditLog audit) {
        this.applications = applications;
        this.permissions = permissions;
        this.roles = roles;
        this.targetTypes = targetTypes;
        this.access = access;
        this.audit = audit;
    }

    public List<String> apply(UserAccount actor, String applicationCode, Manifest manifest) {
        access.requirePlatform(actor);
        List<String> changes = new ArrayList<>();

        Application application = applyApplication(applicationCode, manifest, changes);

        for (TargetTypeSpec spec : manifest.targetTypes()) {
            applyTargetType(spec, changes);
        }
        for (PermissionSpec spec : manifest.permissions()) {
            applyPermission(application, spec, changes);
        }
        // Roles first, then the references between them (assignable roles may point at roles defined later).
        for (RoleSpec spec : manifest.roles()) {
            applyRole(application, spec, changes);
        }
        for (RoleSpec spec : manifest.roles()) {
            Role role = sharedRole(application, spec.code());
            Set<Role> assignable = spec.assigns().stream()
                    .map(ref -> resolveRole(application, ref))
                    .collect(Collectors.toCollection(LinkedHashSet::new));
            if (!roleIds(role.getAssignableRoles()).equals(roleIds(assignable))) {
                AclAdminService.requireNoCycle(role, assignable);
                role.replaceAssignableRoles(assignable);
                changes.add("role %s assigns %s".formatted(spec.code(), new TreeSet<>(spec.assigns())));
            }
            Set<RoleLimit> limits = AclAdminService.resolveLimits(role, spec.limits());
            if (!describe(role.getLimits()).equals(describe(limits))) {
                role.replaceLimits(limits);
                changes.add("role %s limits %s".formatted(spec.code(), describe(limits)));
            }
        }
        for (AssignableBySpec spec : manifest.assignableBy()) {
            Role manager = resolveRole(application, spec.role());
            Set<Role> assignable = new LinkedHashSet<>(manager.getAssignableRoles());
            boolean added = false;
            for (String ref : spec.assigns()) {
                added |= assignable.add(resolveRole(application, ref));
            }
            if (added) {
                AclAdminService.requireNoCycle(manager, assignable);
                manager.replaceAssignableRoles(assignable);
                changes.add("%s can now assign %s".formatted(spec.role(), new TreeSet<>(spec.assigns())));
            }
        }

        audit.record(actor.getId(), "catalog.applied", applicationCode,
                changes.isEmpty() ? "no changes" : String.join("; ", changes));
        return changes;
    }

    private Application applyApplication(String code, Manifest manifest, List<String> changes) {
        Application application = applications.findByCode(code).orElse(null);
        if (application == null) {
            changes.add("application created");
            return applications.save(new Application(code, manifest.name(), manifest.description()));
        }
        if (!Objects.equals(application.getName(), manifest.name())
                || !Objects.equals(application.getDescription(), manifest.description())) {
            application.update(manifest.name(), manifest.description());
            changes.add("application updated");
        }
        return application;
    }

    private void applyTargetType(TargetTypeSpec spec, List<String> changes) {
        TargetType parent = spec.parent() == null ? null : targetTypes.findByCodeAndTenantIsNull(spec.parent())
                .orElseThrow(() -> new BadRequestException("Target type '%s' needs parent '%s', which is not defined"
                        .formatted(spec.code(), spec.parent())));
        var existing = targetTypes.findByCodeAndTenantIsNull(spec.code());
        if (existing.isEmpty()) {
            targetTypes.save(new TargetType(spec.code(), spec.name() == null ? spec.code() : spec.name(), parent, null));
            changes.add("target type %s created".formatted(spec.code()));
            return;
        }
        String currentParent = existing.get().getParent() == null ? null : existing.get().getParent().getCode();
        if (!Objects.equals(currentParent, spec.parent())) {
            throw new ConflictException("Target type '%s' has parent '%s', manifest says '%s'"
                    .formatted(spec.code(), currentParent, spec.parent()));
        }
    }

    private void applyPermission(Application application, PermissionSpec spec, List<String> changes) {
        var existing = permissions.findByApplicationAndCodeIn(application, Set.of(spec.code())).stream().findFirst();
        if (existing.isEmpty()) {
            permissions.save(new Permission(application, spec.code(), spec.description(), spec.limited()));
            changes.add("permission %s created%s".formatted(spec.code(), spec.limited() ? " (limited)" : ""));
        }
        else if (existing.get().isLimited() != spec.limited()) {
            throw new ConflictException("Permission '%s' is %slimited; changing that needs a migration"
                    .formatted(spec.code(), existing.get().isLimited() ? "" : "not "));
        }
    }

    private void applyRole(Application application, RoleSpec spec, List<String> changes) {
        Role role = roles.findByApplicationAndCodeAndTenantIsNull(application, spec.code()).orElse(null);
        Set<Permission> wanted = new HashSet<>(permissions.findByApplicationAndCodeIn(application, spec.permissions()));
        if (wanted.size() != spec.permissions().size()) {
            Set<String> missing = new TreeSet<>(spec.permissions());
            wanted.forEach(permission -> missing.remove(permission.getCode()));
            throw new BadRequestException("Role '%s' uses undefined permissions %s".formatted(spec.code(), missing));
        }
        if (role == null) {
            roles.save(new Role(application, spec.code(), spec.name(), wanted, null));
            changes.add("role %s created".formatted(spec.code()));
            return;
        }
        if (!Objects.equals(role.getName(), spec.name())) {
            role.rename(spec.name());
            changes.add("role %s renamed".formatted(spec.code()));
        }
        if (!permissionIds(role.getPermissions()).equals(permissionIds(wanted))) {
            role.replacePermissions(wanted);
            changes.add("role %s permissions updated".formatted(spec.code()));
        }
    }

    /** {@code role} is a role of this application, or {@code application/role} for another application's shared role. */
    private Role resolveRole(Application application, String reference) {
        int slash = reference.indexOf('/');
        if (slash < 0) {
            return sharedRole(application, reference);
        }
        Application other = applications.findByCode(reference.substring(0, slash))
                .orElseThrow(() -> new NotFoundException("Application '%s' not found".formatted(reference.substring(0, slash))));
        return sharedRole(other, reference.substring(slash + 1));
    }

    private Role sharedRole(Application application, String code) {
        return roles.findByApplicationAndCodeAndTenantIsNull(application, code)
                .orElseThrow(() -> new BadRequestException("Role '%s/%s' is not defined".formatted(application.getCode(), code)));
    }

    private static Set<Long> roleIds(Set<Role> roles) {
        return roles.stream().map(Role::getId).collect(Collectors.toSet());
    }

    private static Set<Long> permissionIds(Set<Permission> permissions) {
        return permissions.stream().map(Permission::getId).collect(Collectors.toSet());
    }

    private static Set<String> describe(Set<RoleLimit> limits) {
        return limits.stream()
                .map(l -> "%s %s %s".formatted(l.getPermission().getCode(), l.getCurrency(),
                        l.getMaxAmount() == null ? "unlimited" : l.getMaxAmount().stripTrailingZeros().toPlainString()))
                .collect(Collectors.toCollection(TreeSet::new));
    }

    public record Manifest(String name, String description, List<TargetTypeSpec> targetTypes,
            List<PermissionSpec> permissions, List<RoleSpec> roles, List<AssignableBySpec> assignableBy,
            Map<String, Object> keycloak) {

        public Manifest {
            targetTypes = targetTypes == null ? List.of() : targetTypes;
            permissions = permissions == null ? List.of() : permissions;
            roles = roles == null ? List.of() : roles;
            assignableBy = assignableBy == null ? List.of() : assignableBy;
        }
    }

    public record TargetTypeSpec(String code, String name, String parent) {
    }

    public record PermissionSpec(String code, String description, Boolean limited) {

        public PermissionSpec {
            limited = Boolean.TRUE.equals(limited);
        }
    }

    /** {@code assigns}: roles holders may assign, making this a manager role (transitive down the chain). */
    public record RoleSpec(String code, String name, List<String> permissions, List<String> assigns,
            List<AclAdminService.LimitSpec> limits) {

        public RoleSpec {
            permissions = permissions == null ? List.of() : permissions;
            assigns = assigns == null ? List.of() : assigns;
            limits = limits == null ? List.of() : limits;
        }
    }

    /** Adds this application's roles to another (e.g. alensi-identity) role's assignable roles. */
    public record AssignableBySpec(String role, List<String> assigns) {
    }
}
