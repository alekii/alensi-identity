package io.alensi.identity.config;

import java.util.Set;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("alensi.identity")
public record IdentityProperties(Keycloak keycloak, Set<String> bootstrapAdmins) {

    public IdentityProperties {
        bootstrapAdmins = bootstrapAdmins == null ? Set.of() : Set.copyOf(bootstrapAdmins);
    }

    public record Keycloak(String baseUrl, String realm) {
    }
}
