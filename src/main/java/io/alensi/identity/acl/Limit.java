package io.alensi.identity.acl;

import java.math.BigDecimal;

/** A limit on a permission in one currency. {@code maxAmount == null} means unlimited. */
public record Limit(String permission, String currency, BigDecimal maxAmount) {

    public boolean isUnlimited() {
        return maxAmount == null;
    }

    public boolean allows(BigDecimal amount) {
        return isUnlimited() || amount.compareTo(maxAmount) <= 0;
    }

    /** The more generous of two limits for the same permission and currency. */
    Limit max(Limit other) {
        if (isUnlimited() || other.isUnlimited()) {
            return new Limit(permission, currency, null);
        }
        return maxAmount.compareTo(other.maxAmount) >= 0 ? this : other;
    }
}
