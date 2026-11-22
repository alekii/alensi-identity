package io.alensi.identity.user;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import io.alensi.identity.config.IdentityProperties;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/** Reads accounts from the Keycloak Admin API using this service's own service account. */
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
