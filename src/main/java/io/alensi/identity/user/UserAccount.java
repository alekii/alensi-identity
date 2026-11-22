package io.alensi.identity.user;

import java.time.Instant;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

/**
 * Local mirror of a Keycloak account. {@code id} is the Keycloak subject, so lightweight
 * access tokens only need to carry {@code sub}.
 */
@Entity
@Table(name = "users")
public class UserAccount {

    @Id
    private UUID id;

    @Column(nullable = false, unique = true)
    private String username;

    private String email;

    private String name;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private UserStatus status = UserStatus.ACTIVE;

    private Instant expiresAt;

    private Instant lastSeenAt;

    @CreationTimestamp
    private Instant createdAt;

    @UpdateTimestamp
    private Instant updatedAt;

    protected UserAccount() {
    }

    public UserAccount(UUID id, String username, String email, String name) {
        this.id = id;
        this.username = username;
        this.email = email;
        this.name = name;
    }

    public boolean isActiveAt(Instant now) {
        return status == UserStatus.ACTIVE && (expiresAt == null || expiresAt.isAfter(now));
    }

    public void syncFrom(KeycloakUser user) {
        this.username = user.username();
        this.email = user.email();
        this.name = user.displayName();
    }

    public void markSeen(Instant now) {
        this.lastSeenAt = now;
    }

    public void setStatus(UserStatus status) {
        this.status = status;
    }

    public void setExpiresAt(Instant expiresAt) {
        this.expiresAt = expiresAt;
    }

    public UUID getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public String getEmail() {
        return email;
    }

    public String getName() {
        return name;
    }

    public UserStatus getStatus() {
        return status;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public Instant getLastSeenAt() {
        return lastSeenAt;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }
}
