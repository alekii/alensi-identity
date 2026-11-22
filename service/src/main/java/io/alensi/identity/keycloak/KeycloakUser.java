package io.alensi.identity.keycloak;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** The subset of Keycloak's UserRepresentation this service uses. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record KeycloakUser(UUID id, String username, String email, String firstName, String lastName, boolean enabled,
        List<String> requiredActions) {

    public KeycloakUser {
        requiredActions = requiredActions == null ? List.of() : List.copyOf(requiredActions);
    }

    public KeycloakUser(UUID id, String username, String email, String firstName, String lastName, boolean enabled) {
        this(id, username, email, firstName, lastName, enabled, List.of());
    }

    /** Invited but has not yet chosen a password: the invite can be (re)sent. */
    public boolean isPendingSetup() {
        return requiredActions.contains(KeycloakAdminClient.UPDATE_PASSWORD);
    }

    public String displayName() {
        String name = Stream.of(firstName, lastName)
                .filter(part -> part != null && !part.isBlank())
                .collect(Collectors.joining(" "));
        return name.isEmpty() ? null : name;
    }
}
