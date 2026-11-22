package io.alensi.identity.user;

import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** The subset of Keycloak's UserRepresentation this service uses. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record KeycloakUser(UUID id, String username, String email, String firstName, String lastName, boolean enabled) {

    public String displayName() {
        String name = Stream.of(firstName, lastName)
                .filter(part -> part != null && !part.isBlank())
                .collect(Collectors.joining(" "));
        return name.isEmpty() ? null : name;
    }
}
