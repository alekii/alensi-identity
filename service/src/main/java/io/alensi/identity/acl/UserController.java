package io.alensi.identity.acl;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import io.alensi.identity.audit.AuditLog;
import io.alensi.identity.tenant.TenantContext;
import io.alensi.identity.user.UserAccount;
import io.alensi.identity.user.UserAccountRepository;
import io.alensi.identity.user.UserDirectory;
import io.alensi.identity.user.UserProfile;
import io.alensi.identity.user.UserStatus;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/users")
class UserController {

    private final UserDirectory directory;
    private final UserAccountRepository users;
    private final AccessGuard access;
    private final AuditLog audit;
    private final PermissionService permissions;

    UserController(UserDirectory directory, UserAccountRepository users, AccessGuard access, AuditLog audit,
            PermissionService permissions) {
        this.directory = directory;
        this.users = users;
        this.access = access;
        this.audit = audit;
        this.permissions = permissions;
    }

    @GetMapping("/me")
    UserProfile me(UserAccount caller) {
        return UserProfile.of(caller);
    }

    /**
     * Who the caller is and which tenant this request acts in (from the token's organization or
     * {@code X-Alensi-Tenant}); {@code tenant} is null when the caller works in several and chose none.
     */
    @GetMapping("/me/context")
    MeContext context(UserAccount caller, TenantContext context) {
        List<String> tenants = permissions.activeMemberships(caller).stream()
                .map(member -> member.getTenant().getCode())
                .sorted()
                .toList();
        return new MeContext(caller.getId(), caller.getUsername(), context.tenantCode(), tenants);
    }

    record MeContext(UUID id, String username, String tenant, List<String> tenants) {
    }

    @GetMapping("/id/{id}")
    UserProfile byId(UserAccount caller, @PathVariable UUID id) {
        if (!caller.getId().equals(id)) {
            access.requireCanSeeOthers(caller, AccessGuard.USERS_READ);
        }
        UserAccount subject = directory.findById(id);
        access.readScope(caller, subject, AccessGuard.USERS_READ);
        return UserProfile.of(subject);
    }

    @GetMapping("/username/{username}")
    UserProfile byUsername(UserAccount caller, @PathVariable String username) {
        if (!caller.getUsername().equals(username)) {
            access.requireCanSeeOthers(caller, AccessGuard.USERS_READ);
        }
        UserAccount subject = directory.findByUsername(username);
        access.readScope(caller, subject, AccessGuard.USERS_READ);
        return UserProfile.of(subject);
    }

    /**
     * Suspends/reactivates a whole account across every tenant, or sets its expiry. Platform-only;
     * tenants suspend their own memberships via {@code /api/tenants/{tenant}/members/{username}}.
     */
    @PutMapping("/username/{username}/access")
    @Transactional
    UserProfile updateAccess(UserAccount caller, @PathVariable String username,
            @Valid @RequestBody AccessUpdate update) {
        access.requirePlatform(caller);
        UserAccount user = directory.findByUsername(username);
        user.setStatus(update.status());
        user.setExpiresAt(update.expiresAt());
        users.save(user);
        audit.record(caller.getId(), "user.access-updated", username,
                "status=%s expiresAt=%s".formatted(update.status(), update.expiresAt()));
        return UserProfile.of(user);
    }

    record AccessUpdate(@NotNull UserStatus status, Instant expiresAt) {
    }
}
