package io.alensi.identity.user;

import java.time.Instant;
import java.util.UUID;

public record UserProfile(UUID id, String username, String email, String name, UserStatus status,
        Instant expiresAt, Instant lastSeenAt, Instant createdAt, Instant updatedAt) {

    public static UserProfile of(UserAccount user) {
        return new UserProfile(user.getId(), user.getUsername(), user.getEmail(), user.getName(), user.getStatus(),
                user.getExpiresAt(), user.getLastSeenAt(), user.getCreatedAt(), user.getUpdatedAt());
    }
}
