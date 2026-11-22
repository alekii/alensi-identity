package io.alensi.identity.acl;

import java.math.BigDecimal;
import java.util.List;
import java.util.Set;
import java.util.function.Predicate;

import io.alensi.identity.tenant.TenantContext;
import io.alensi.identity.user.AccessGuard;
import io.alensi.identity.user.UserAccount;
import io.alensi.identity.user.UserDirectory;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.PositiveOrZero;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * Manages applications, permissions, roles, targets and grants. Reading the catalog needs only
 * authentication. Catalog changes are platform-only; targets and grants are delegated by scope.
 */
@RestController
@RequestMapping("/api")
class AclAdminController {

    private static final String CODE = "^[A-Za-z0-9][A-Za-z0-9._:-]*$";

    private final AclCatalog catalog;
    private final AclAdminService admin;
    private final UserDirectory directory;
    private final AccessGuard access;

    AclAdminController(AclCatalog catalog, AclAdminService admin, UserDirectory directory, AccessGuard access) {
        this.catalog = catalog;
        this.admin = admin;
        this.directory = directory;
        this.access = access;
    }

    @GetMapping("/applications")
    List<AclViews.ApplicationView> applications(UserAccount caller) {
        return catalog.applications();
    }

    @PostMapping("/applications")
    @ResponseStatus(HttpStatus.CREATED)
    AclViews.ApplicationView createApplication(UserAccount caller, @Valid @RequestBody NewApplication body) {
        access.requirePlatform(caller);
        return admin.createApplication(caller, body.code(), body.name(), body.description());
    }

    @GetMapping("/applications/{application}")
    AclViews.ApplicationView application(UserAccount caller, @PathVariable String application) {
        return catalog.application(application);
    }

    @GetMapping("/applications/{application}/permissions")
    List<AclViews.PermissionView> permissions(UserAccount caller, @PathVariable String application) {
        return catalog.permissions(application);
    }

    @PostMapping("/applications/{application}/permissions")
    @ResponseStatus(HttpStatus.CREATED)
    AclViews.PermissionView createPermission(UserAccount caller, @PathVariable String application,
            @Valid @RequestBody NewPermission body) {
        access.requirePlatform(caller);
        return admin.createPermission(caller, application, body.code(), body.description(), body.limited());
    }

    @GetMapping("/applications/{application}/roles")
    List<AclViews.RoleView> roles(UserAccount caller, TenantContext context, @PathVariable String application) {
        Predicate<String> visible = visibleTenants(caller, context);
        return catalog.roles(application).stream().filter(role -> role.tenant() == null || visible.test(role.tenant())).toList();
    }

    @PostMapping("/applications/{application}/roles")
    @ResponseStatus(HttpStatus.CREATED)
    AclViews.RoleView createRole(UserAccount caller, @PathVariable String application,
            @Valid @RequestBody NewRole body) {
        return admin.createRole(caller, application, body.code(), body.name(), body.permissions(), body.tenant(),
                limits(body.limits()));
    }

    /**
     * Sets which roles holders of a role may assign, making it a manager role. {@code tenant} selects
     * a tenant-owned role; omit it for shared roles.
     */
    @PutMapping("/applications/{application}/roles/{role}/assignable-roles")
    AclViews.RoleView setAssignableRoles(UserAccount caller, @PathVariable String application,
            @PathVariable String role, @RequestParam(required = false) String tenant,
            @Valid @RequestBody AssignableRoles body) {
        return admin.setAssignableRoles(caller, application, role, tenant, body.roles());
    }

    @PutMapping("/applications/{application}/roles/{role}/limits")
    AclViews.RoleView setLimits(UserAccount caller, @PathVariable String application, @PathVariable String role,
            @RequestParam(required = false) String tenant, @Valid @RequestBody Limits body) {
        return admin.setLimits(caller, application, role, tenant, limits(body.limits()));
    }

    @GetMapping("/target-types")
    List<AclViews.TargetTypeView> targetTypes(UserAccount caller, TenantContext context) {
        Predicate<String> visible = visibleTenants(caller, context);
        return catalog.targetTypes().stream().filter(type -> type.tenant() == null || visible.test(type.tenant())).toList();
    }

    @PostMapping("/target-types")
    @ResponseStatus(HttpStatus.CREATED)
    AclViews.TargetTypeView createTargetType(UserAccount caller, @Valid @RequestBody NewTargetType body) {
        return admin.createTargetType(caller, body.code(), body.name(), body.parent(), body.tenant());
    }

    @GetMapping("/targets")
    List<AclViews.TargetView> targets(UserAccount caller, TenantContext context) {
        Predicate<String> visible = visibleTenants(caller, context);
        return catalog.targets().stream().filter(target -> visible.test(target.tenant())).toList();
    }

    @PostMapping("/targets")
    @ResponseStatus(HttpStatus.CREATED)
    AclViews.TargetView createTarget(UserAccount caller, @Valid @RequestBody NewTarget body) {
        return admin.createTarget(caller, body.code(), body.name(), body.type(), body.parent());
    }

    @GetMapping("/users/{username}/grants")
    List<AclViews.GrantView> grants(UserAccount caller, @PathVariable String username) {
        if (!caller.getUsername().equals(username)) {
            access.requireCanSeeOthers(caller, AccessGuard.PERMISSIONS_READ);
        }
        UserAccount subject = directory.findByUsername(username);
        Scope scope = access.readScope(caller, subject, AccessGuard.PERMISSIONS_READ);
        return catalog.grants(subject).stream().filter(grant -> scope.covers(grant.target())).toList();
    }

    @PostMapping("/users/{username}/grants")
    @ResponseStatus(HttpStatus.CREATED)
    AclViews.GrantView grant(UserAccount caller, @PathVariable String username, @Valid @RequestBody NewGrant body) {
        access.requireCanSeeOthers(caller, AccessGuard.ROLES_MANAGE);
        return admin.grant(caller, directory.findByUsername(username), body.application(), body.role(), body.target());
    }

    @DeleteMapping("/users/{username}/grants/{grantId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    void revoke(UserAccount caller, @PathVariable String username, @PathVariable long grantId) {
        access.requireCanSeeOthers(caller, AccessGuard.ROLES_MANAGE);
        admin.revoke(caller, directory.findByUsername(username), grantId);
    }

    record NewApplication(@NotBlank @Size(max = 64) @Pattern(regexp = CODE) String code,
            @NotBlank @Size(max = 255) String name, String description) {
    }

    /** {@code limited} permissions (e.g. claims.approve) carry monetary limits per role and currency. */
    record NewPermission(@NotBlank @Size(max = 128) @Pattern(regexp = CODE) String code, String description,
            Boolean limited) {

        NewPermission {
            limited = Boolean.TRUE.equals(limited);
        }
    }

    /** {@code tenant} makes the role private to a tenant; omit it for shared roles (platform-only). */
    record NewRole(@NotBlank @Size(max = 64) @Pattern(regexp = CODE) String code,
            @NotBlank @Size(max = 255) String name, @NotEmpty Set<@NotBlank String> permissions, String tenant,
            List<@Valid LimitBody> limits) {
    }

    record Limits(@NotNull List<@Valid LimitBody> limits) {
    }

    /** {@code maxAmount} omitted or null means unlimited. */
    record LimitBody(@NotBlank String permission, @NotBlank @Pattern(regexp = "^[A-Z]{3}$") String currency,
            @PositiveOrZero BigDecimal maxAmount) {
    }

    /** {@code tenant} makes the type private to a tenant; omit it for shared types (platform-only). */
    record NewTargetType(@NotBlank @Size(max = 64) @Pattern(regexp = CODE) String code,
            @NotBlank @Size(max = 255) String name, String parent, String tenant) {
    }

    record NewTarget(@NotBlank @Size(max = 64) @Pattern(regexp = CODE) String code,
            @NotBlank @Size(max = 255) String name, @NotBlank String type, String parent) {
    }

    /** The request's tenant if one was chosen, else every tenant the caller works in. */
    private Predicate<String> visibleTenants(UserAccount caller, TenantContext context) {
        if (context.tenant() != null) {
            return context.tenantCode()::equals;
        }
        Set<String> tenants = access.visibleTenants(caller);
        return tenants == null ? tenant -> true : tenants::contains;
    }

    private static List<AclAdminService.LimitSpec> limits(List<LimitBody> limits) {
        return limits == null ? List.of() : limits.stream()
                .map(limit -> new AclAdminService.LimitSpec(limit.permission(), limit.currency(), limit.maxAmount()))
                .toList();
    }

    record AssignableRoles(@NotNull List<@Valid RoleRef> roles) {
    }

    /** {@code target} omitted (or {@code "*"}) grants the role on all targets. */
    record NewGrant(@NotBlank String application, @NotBlank String role, String target) {

        NewGrant {
            if (PermissionEvaluator.WILDCARD.equals(target)) {
                target = null;
            }
        }
    }
}
