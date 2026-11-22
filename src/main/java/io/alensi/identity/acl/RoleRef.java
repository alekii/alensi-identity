package io.alensi.identity.acl;

import jakarta.validation.constraints.NotBlank;

/** A role identified by its application, e.g. {@code alensi-insure/agent}. */
public record RoleRef(@NotBlank String application, @NotBlank String role) {

    @Override
    public String toString() {
        return application + "/" + role;
    }
}
