package io.alensi.identity.user;

import java.time.Instant;
import java.util.UUID;

import io.alensi.identity.audit.AuditLog;
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

    UserController(UserDirectory directory, UserAccountRepository users, AccessGuard access, AuditLog audit) {
        this.directory = directory;
        this.users = users;
        this.access = access;
        this.audit = audit;
    }

    @GetMapping("/me")
    UserProfile me(UserAccount caller) {
        return UserProfile.of(caller);
    }

    @GetMapping("/id/{id}")
    UserProfile byId(UserAccount caller, @PathVariable UUID id) {
        if (!caller.getId().equals(id)) {
            access.requireAnywhere(caller, AccessGuard.USERS_READ);
        }
        UserAccount subject = directory.findById(id);
        access.readScope(caller, subject, AccessGuard.USERS_READ);
        return UserProfile.of(subject);
    }

    @GetMapping("/username/{username}")
    UserProfile byUsername(UserAccount caller, @PathVariable String username) {
        if (!caller.getUsername().equals(username)) {
            access.requireAnywhere(caller, AccessGuard.USERS_READ);
        }
        UserAccount subject = directory.findByUsername(username);
        access.readScope(caller, subject, AccessGuard.USERS_READ);
        return UserProfile.of(subject);
    }

    /**
     * Suspends/reactivates an account or sets its expiry. Takes effect on the next request. Only
     * allowed for admins whose scope covers every grant the user holds.
     */
    @PutMapping("/username/{username}/access")
    @Transactional
    UserProfile updateAccess(UserAccount caller, @PathVariable String username,
            @Valid @RequestBody AccessUpdate update) {
        access.requireAnywhere(caller, AccessGuard.USERS_MANAGE);
        UserAccount user = directory.findByUsername(username);
        access.requireAccountManagement(caller, user);
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
