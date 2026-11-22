package io.alensi.identity.config;

import java.time.Duration;
import java.util.Set;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("alensi.identity")
public record IdentityProperties(Keycloak keycloak, Set<String> bootstrapAdmins, Onboarding onboarding) {

    public IdentityProperties {
        bootstrapAdmins = bootstrapAdmins == null ? Set.of() : Set.copyOf(bootstrapAdmins);
    }

    public record Keycloak(String baseUrl, String realm) {
    }

    /** Invite emails: valid for {@code inviteLifespan}, landing on {@code redirectUri} of {@code clientId} when done. */
    public record Onboarding(String clientId, String redirectUri, Duration inviteLifespan) {
    }
}
