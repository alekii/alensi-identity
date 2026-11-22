package io.alensi.identity.client;

import java.math.BigDecimal;
import java.util.List;

/**
 * Answer for a permission on a target. For limited permissions (e.g. {@code claims.approve})
 * {@code limits} holds the user's best limit per currency there, so a refusal can be routed up
 * ("escalate to someone whose limit covers it"); {@code null} for permissions without limits.
 */
public record Decision(boolean allowed, List<Limit> limits) {

    /** {@code maxAmount == null} means unlimited. */
    public record Limit(String permission, String currency, BigDecimal maxAmount) {
    }
}
