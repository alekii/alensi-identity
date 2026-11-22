package io.alensi.identity.tenant;

/**
 * The tenant a request acts in, chosen by the token's {@code organization} claim or the
 * {@code X-Alensi-Tenant} header, and always one the caller is an active member of. {@code tenant}
 * is {@code null} when no tenant was chosen and the caller works in several.
 */
public record TenantContext(Tenant tenant) {

    public static final String HEADER = "X-Alensi-Tenant";

    public Long tenantId() {
        return tenant == null ? null : tenant.getId();
    }

    public String tenantCode() {
        return tenant == null ? null : tenant.getCode();
    }
}
