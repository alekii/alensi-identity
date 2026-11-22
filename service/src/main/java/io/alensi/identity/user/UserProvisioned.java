package io.alensi.identity.user;

import java.util.UUID;

/**
 * Published when a Keycloak account is first seen and a local account is created for it.
 * Delivered synchronously, within the provisioning transaction.
 */
public record UserProvisioned(UUID userId, String username) {
}
