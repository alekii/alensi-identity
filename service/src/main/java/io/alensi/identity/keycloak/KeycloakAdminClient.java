package io.alensi.identity.keycloak;

import java.net.URI;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import io.alensi.identity.config.IdentityProperties;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/**
 * Reads accounts and manages organizations through the Keycloak Admin API, using this service's own
 * service account (realm-management: view-users, query-users, manage-users, manage-organizations).
 * Keycloak requires manage-users to add organization members; it is also what onboarding needs.
 * Narrow it with fine-grained admin permissions if the service's blast radius must shrink.
 */
@Component
public class KeycloakAdminClient {

    public static final String UPDATE_PASSWORD = "UPDATE_PASSWORD";
    public static final String VERIFY_EMAIL = "VERIFY_EMAIL";
    public static final String CONFIGURE_TOTP = "CONFIGURE_TOTP";

    private static final String REGISTRATION_ID = "keycloak-admin";

    private final RestClient restClient;
    private final OAuth2AuthorizedClientManager authorizedClientManager;

    KeycloakAdminClient(RestClient.Builder builder, IdentityProperties properties,
            OAuth2AuthorizedClientManager authorizedClientManager) {
        this.restClient = builder
                .baseUrl(properties.keycloak().baseUrl() + "/admin/realms/" + properties.keycloak().realm())
                .requestInterceptor((request, body, execution) -> {
                    request.getHeaders().setBearerAuth(accessToken());
                    return execution.execute(request, body);
                })
                .build();
        this.authorizedClientManager = authorizedClientManager;
    }

    public Optional<KeycloakUser> findById(UUID id) {
        return Optional.ofNullable(restClient.get()
                .uri("/users/{id}", id)
                .exchange((request, response) -> {
                    if (response.getStatusCode() == HttpStatus.NOT_FOUND) {
                        return null;
                    }
                    if (response.getStatusCode().isError()) {
                        throw new IllegalStateException("Keycloak Admin API returned " + response.getStatusCode());
                    }
                    return response.bodyTo(KeycloakUser.class);
                }));
    }

    public Optional<KeycloakUser> findByUsername(String username) {
        List<KeycloakUser> users = restClient.get()
                .uri(uri -> uri.path("/users").queryParam("username", username).queryParam("exact", true).build())
                .retrieve()
                .body(new ParameterizedTypeReference<>() {
                });
        return users == null ? Optional.empty() : users.stream().findFirst();
    }

    public Optional<KeycloakUser> findByEmail(String email) {
        List<KeycloakUser> users = restClient.get()
                .uri(uri -> uri.path("/users").queryParam("email", email).queryParam("exact", true).build())
                .retrieve()
                .body(new ParameterizedTypeReference<>() {
                });
        return users == null ? Optional.empty() : users.stream().findFirst();
    }

    /** Creates an enabled account with no credentials yet; the user sets them up from the invite. */
    public KeycloakUser createUser(String email, String firstName, String lastName, String phoneNumber,
            List<String> requiredActions) {
        Map<String, Object> representation = new LinkedHashMap<>();
        representation.put("username", email);
        representation.put("email", email);
        representation.put("firstName", firstName);
        representation.put("lastName", lastName);
        representation.put("enabled", true);
        representation.put("requiredActions", requiredActions);
        if (phoneNumber != null) {
            representation.put("attributes", Map.of("phoneNumber", List.of(phoneNumber)));
        }
        URI location = restClient.post()
                .uri("/users")
                .body(representation)
                .retrieve()
                .toBodilessEntity()
                .getHeaders()
                .getLocation();
        if (location == null) {
            throw new IllegalStateException("Keycloak did not return the new user");
        }
        String path = location.getPath();
        return new KeycloakUser(UUID.fromString(path.substring(path.lastIndexOf('/') + 1)), email, email, firstName,
                lastName, true, requiredActions);
    }

    /**
     * Emails the user a link to complete {@code actions} (e.g. set a password), valid for
     * {@code lifespan}, returning to {@code redirectUri} of {@code clientId} afterwards.
     */
    public void sendActionsEmail(UUID userId, List<String> actions, Duration lifespan, String clientId,
            String redirectUri) {
        restClient.put()
                .uri(uri -> uri.path("/users/{id}/execute-actions-email")
                        .queryParam("lifespan", lifespan.toSeconds())
                        .queryParam("client_id", clientId)
                        .queryParam("redirect_uri", redirectUri)
                        .build(userId))
                .body(actions)
                .retrieve()
                .toBodilessEntity();
    }

    /**
     * Id of the organization with this alias, if it exists. Keycloak's exact search matches names, not
     * aliases, so this searches loosely and filters on the alias.
     */
    public Optional<String> findOrganizationId(String alias) {
        List<Map<String, Object>> organizations = restClient.get()
                .uri(uri -> uri.path("/organizations").queryParam("search", alias).queryParam("briefRepresentation", true).build())
                .retrieve()
                .body(new ParameterizedTypeReference<>() {
                });
        return organizations == null ? Optional.empty() : organizations.stream()
                .filter(organization -> alias.equals(organization.get("alias")))
                .map(organization -> (String) organization.get("id"))
                .findFirst();
    }

    /** Creates an organization and returns its id. */
    public String createOrganization(String name, String alias) {
        URI location = restClient.post()
                .uri("/organizations")
                .body(Map.of("name", name, "alias", alias, "enabled", true))
                .retrieve()
                .toBodilessEntity()
                .getHeaders()
                .getLocation();
        if (location == null) {
            throw new IllegalStateException("Keycloak did not return the new organization '%s'".formatted(alias));
        }
        String path = location.getPath();
        return path.substring(path.lastIndexOf('/') + 1);
    }

    /** Adds the user to the organization; already being a member is fine. */
    public void addOrganizationMember(String organizationId, UUID userId) {
        restClient.post()
                .uri("/organizations/{id}/members", organizationId)
                .body("\"" + userId + "\"")
                .header("Content-Type", "application/json")
                .exchange((request, response) -> {
                    if (response.getStatusCode().isError() && response.getStatusCode() != HttpStatus.CONFLICT) {
                        throw new IllegalStateException("Keycloak Admin API returned " + response.getStatusCode());
                    }
                    return null;
                });
    }

    /** Removes the user from the organization; not being a member is fine. */
    public void removeOrganizationMember(String organizationId, UUID userId) {
        restClient.delete()
                .uri("/organizations/{id}/members/{userId}", organizationId, userId)
                .exchange((request, response) -> {
                    if (response.getStatusCode().isError() && response.getStatusCode() != HttpStatus.NOT_FOUND) {
                        throw new IllegalStateException("Keycloak Admin API returned " + response.getStatusCode());
                    }
                    return null;
                });
    }

    private String accessToken() {
        var request = OAuth2AuthorizeRequest.withClientRegistrationId(REGISTRATION_ID)
                .principal("alensi-identity")
                .build();
        var client = authorizedClientManager.authorize(request);
        if (client == null) {
            throw new IllegalStateException("Unable to obtain a Keycloak admin access token");
        }
        return client.getAccessToken().getTokenValue();
    }
}
