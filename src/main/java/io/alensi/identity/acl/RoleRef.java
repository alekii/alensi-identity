package io.alensi.identity.acl;

import jakarta.validation.constraints.NotBlank;

/**
 * A role identified by its application and, for tenant-owned roles, the tenant, e.g.
 * {@code alensi-insure/senior-agent@JUB}. When {@code tenant} is omitted it defaults to a shared
 * role of that code, else the referencing role's own tenant.
 */
public record RoleRef(@NotBlank String application, @NotBlank String role, String tenant) {

    @Override
    public String toString() {
        return application + "/" + role + (tenant == null ? "" : "@" + tenant);
    }
}
