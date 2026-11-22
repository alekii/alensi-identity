package io.alensi.identity.user;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

import io.alensi.identity.audit.AuditLog;
import io.alensi.identity.keycloak.KeycloakAdminClient;
import io.alensi.identity.keycloak.KeycloakUser;
import io.alensi.identity.web.NotFoundException;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Maps Keycloak subjects to local accounts. Accounts are provisioned just in time from the Keycloak
 * Admin API, which keeps access tokens down to {@code sub}.
 */
@Service
public class UserDirectory {

    private static final Duration LAST_SEEN_RESOLUTION = Duration.ofMinutes(5);

    private final UserAccountRepository users;
    private final KeycloakAdminClient keycloak;
    private final AuditLog audit;
    private final ApplicationEventPublisher events;
    private final Clock clock;

    UserDirectory(UserAccountRepository users, KeycloakAdminClient keycloak, AuditLog audit,
            ApplicationEventPublisher events) {
        this.users = users;
        this.keycloak = keycloak;
        this.audit = audit;
        this.events = events;
        this.clock = Clock.systemUTC();
    }

    /** Resolves the authenticated caller, rejecting suspended or expired accounts. */
    @Transactional
    public UserAccount resolveCaller(Jwt jwt) {
        UUID id = UUID.fromString(jwt.getSubject());
        UserAccount user = users.findById(id).orElseGet(() -> provision(keycloak.findById(id)
                .orElseThrow(() -> new AccessDeniedException("Unknown subject"))));
        Instant now = clock.instant();
        if (!user.isActiveAt(now)) {
            throw new AccessDeniedException("Account is suspended or expired");
        }
        if (user.getLastSeenAt() == null || user.getLastSeenAt().isBefore(now.minus(LAST_SEEN_RESOLUTION))) {
            user.markSeen(now);
        }
        return user;
    }

    @Transactional
    public UserAccount findByUsername(String username) {
        return users.findByUsername(username).orElseGet(() -> provision(keycloak.findByUsername(username)
                .orElseThrow(() -> new NotFoundException("User '%s' not found".formatted(username)))));
    }

    @Transactional(readOnly = true)
    public UserAccount findById(UUID id) {
        return users.findById(id).orElseThrow(() -> new NotFoundException("User '%s' not found".formatted(id)));
    }

    /** The local account for a Keycloak user, provisioned if this is the first time we see them. */
    @Transactional
    public UserAccount findOrProvision(KeycloakUser source) {
        return users.findById(source.id()).orElseGet(() -> provision(source));
    }

    private UserAccount provision(KeycloakUser source) {
        UserAccount user = users.findById(source.id())
                .orElseGet(() -> new UserAccount(source.id(), source.username(), source.email(), source.displayName()));
        user.syncFrom(source);
        user = users.save(user);
        audit.record(null, "user.provisioned", user.getUsername(), "id=" + user.getId());
        events.publishEvent(new UserProvisioned(user.getId(), user.getUsername()));
        return user;
    }
}
