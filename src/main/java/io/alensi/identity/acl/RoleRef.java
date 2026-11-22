package io.alensi.identity.acl;

import jakarta.validation.constraints.NotBlank;

/**
 * A role identified by its application and, for company-owned roles, the owning company, e.g.
 * {@code alensi-insure/senior-agent@JUB}.
 */
public record RoleRef(@NotBlank String application, @NotBlank String role, String owner) {

    @Override
    public String toString() {
        return application + "/" + role + (owner == null ? "" : "@" + owner);
    }
}
