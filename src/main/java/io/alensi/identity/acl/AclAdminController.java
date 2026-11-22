package io.alensi.identity.acl;

import java.util.List;
import java.util.Set;

import io.alensi.identity.user.AccessGuard;
import io.alensi.identity.user.UserAccount;
import io.alensi.identity.user.UserDirectory;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
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
        return admin.createPermission(caller, application, body.code(), body.description());
    }

    @GetMapping("/applications/{application}/roles")
    List<AclViews.RoleView> roles(UserAccount caller, @PathVariable String application) {
        return catalog.roles(application);
    }

    @PostMapping("/applications/{application}/roles")
    @ResponseStatus(HttpStatus.CREATED)
    AclViews.RoleView createRole(UserAccount caller, @PathVariable String application,
            @Valid @RequestBody NewRole body) {
        access.requirePlatform(caller);
        return admin.createRole(caller, application, body.code(), body.name(), body.permissions());
    }

    @PutMapping("/applications/{application}/roles/{role}/assignable-roles")
    AclViews.RoleView setAssignableRoles(UserAccount caller, @PathVariable String application,
            @PathVariable String role, @Valid @RequestBody AssignableRoles body) {
        access.requirePlatform(caller);
        return admin.setAssignableRoles(caller, application, role, body.roles());
    }

    @GetMapping("/target-types")
    List<AclViews.TargetTypeView> targetTypes(UserAccount caller) {
        return catalog.targetTypes();
    }

    @PostMapping("/target-types")
    @ResponseStatus(HttpStatus.CREATED)
    AclViews.TargetTypeView createTargetType(UserAccount caller, @Valid @RequestBody NewTargetType body) {
        access.requirePlatform(caller);
        return admin.createTargetType(caller, body.code(), body.name(), body.parent());
    }

    @GetMapping("/targets")
    List<AclViews.TargetView> targets(UserAccount caller) {
        return catalog.targets();
    }

    @PostMapping("/targets")
    @ResponseStatus(HttpStatus.CREATED)
    AclViews.TargetView createTarget(UserAccount caller, @Valid @RequestBody NewTarget body) {
        return admin.createTarget(caller, body.code(), body.name(), body.type(), body.parent());
    }

    @GetMapping("/users/{username}/grants")
    List<AclViews.GrantView> grants(UserAccount caller, @PathVariable String username) {
        if (!caller.getUsername().equals(username)) {
            access.requireAnywhere(caller, AccessGuard.PERMISSIONS_READ);
        }
        UserAccount subject = directory.findByUsername(username);
        Scope scope = access.readScope(caller, subject, AccessGuard.PERMISSIONS_READ);
        return catalog.grants(subject).stream().filter(grant -> scope.covers(grant.target())).toList();
    }

    @PostMapping("/users/{username}/grants")
    @ResponseStatus(HttpStatus.CREATED)
    AclViews.GrantView grant(UserAccount caller, @PathVariable String username, @Valid @RequestBody NewGrant body) {
        access.requireAnywhere(caller, AccessGuard.USERS_MANAGE);
        return admin.grant(caller, directory.findByUsername(username), body.application(), body.role(), body.target());
    }

    @DeleteMapping("/users/{username}/grants/{grantId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    void revoke(UserAccount caller, @PathVariable String username, @PathVariable long grantId) {
        access.requireAnywhere(caller, AccessGuard.USERS_MANAGE);
        admin.revoke(caller, directory.findByUsername(username), grantId);
    }

    record NewApplication(@NotBlank @Size(max = 64) @Pattern(regexp = CODE) String code,
            @NotBlank @Size(max = 255) String name, String description) {
    }

    record NewPermission(@NotBlank @Size(max = 128) @Pattern(regexp = CODE) String code, String description) {
    }

    record NewRole(@NotBlank @Size(max = 64) @Pattern(regexp = CODE) String code,
            @NotBlank @Size(max = 255) String name, @NotEmpty Set<@NotBlank String> permissions) {
    }

    record NewTargetType(@NotBlank @Size(max = 64) @Pattern(regexp = CODE) String code,
            @NotBlank @Size(max = 255) String name, String parent) {
    }

    record NewTarget(@NotBlank @Size(max = 64) @Pattern(regexp = CODE) String code,
            @NotBlank @Size(max = 255) String name, @NotBlank String type, String parent) {
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
