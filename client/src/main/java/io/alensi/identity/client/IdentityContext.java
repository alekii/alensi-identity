package io.alensi.identity.client;

import java.util.List;
import java.util.UUID;

/**
 * The caller and the tenant this request acts in. {@code tenant} is null when the caller works in
 * several tenants and the request chose none (token organization or {@code X-Alensi-Tenant}).
 */
public record IdentityContext(UUID id, String username, String tenant, List<String> tenants) {
}
