package io.alensi.identity.client;

import java.math.BigDecimal;
import java.net.URI;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;
import org.springframework.web.util.UriBuilder;

/**
 * Calls alensi-identity with an explicit bearer token and tenant. Most code should use
 * {@link AlensiAccess}, which takes both from the current request and caches; use this directly
 * from background jobs (with the service account's token).
 */
public class AlensiIdentityClient {

    public static final String TENANT_HEADER = "X-Alensi-Tenant";

    private static final ParameterizedTypeReference<Map<String, Map<String, Set<String>>>> PERMISSION_MAP =
            new ParameterizedTypeReference<>() {
            };

    private final RestClient rest;
    private final String application;

    public AlensiIdentityClient(RestClient.Builder builder, AlensiIdentityProperties properties) {
        if (properties.baseUrl() == null || properties.application() == null) {
            throw new IllegalStateException("alensi.identity.client.base-url and .application are required");
        }
        this.rest = builder.baseUrl(properties.baseUrl().toString()).build();
        this.application = properties.application();
    }

    /** The token owner's permissions in this application ({@code tenant} null: identity decides). */
    public PermissionMap permissions(String token, String tenant) {
        return permissionsOf("me", token, tenant);
    }

    /**
     * Another user's permissions, e.g. from a background job using the service account's token
     * (which needs {@code identity.permissions.read}).
     */
    public PermissionMap permissionsOf(String username, String token, String tenant) {
        return new PermissionMap(get(token, tenant,
                uri -> uri.path("/api/users/{user}/applications/{app}/permissions").build(username, application),
                PERMISSION_MAP));
    }

    /** Checks a permission on a target; with {@code amount} and {@code currency}, against the user's limit. */
    public Decision decide(String token, String tenant, String permission, String target, BigDecimal amount,
            String currency) {
        return get(token, tenant, uri -> {
            uri.path("/api/users/me/applications/{app}/permissions/{permission}/targets/{target}");
            if (amount != null) {
                uri.queryParam("amount", amount.toPlainString()).queryParam("currency", currency);
            }
            return uri.build(application, permission, target);
        }, ParameterizedTypeReference.forType(Decision.class));
    }

    public IdentityContext context(String token, String tenant) {
        return get(token, tenant, uri -> uri.path("/api/users/me/context").build(),
                ParameterizedTypeReference.forType(IdentityContext.class));
    }

    private <T> T get(String token, String tenant, Function<UriBuilder, URI> uri,
            ParameterizedTypeReference<T> type) {
        try {
            return rest.get()
                    .uri(uri)
                    .headers(headers -> {
                        headers.setBearerAuth(token);
                        if (tenant != null) {
                            headers.set(TENANT_HEADER, tenant);
                        }
                    })
                    .retrieve()
                    .body(type);
        }
        catch (RestClientResponseException e) {
            if (e.getStatusCode().value() == 403) {
                // e.g. a tenant the caller is not an active member of: a refusal, not an outage
                throw new AccessDeniedException("alensi-identity refused: " + e.getResponseBodyAsString());
            }
            throw new AlensiIdentityException(e.getStatusCode().value(),
                    "alensi-identity returned %d: %s".formatted(e.getStatusCode().value(), e.getResponseBodyAsString()), e);
        }
        catch (ResourceAccessException e) {
            throw new AlensiIdentityException(0, "alensi-identity is unreachable", e);
        }
    }
}
