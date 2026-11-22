package io.alensi.identity.user;

import java.net.URI;
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
