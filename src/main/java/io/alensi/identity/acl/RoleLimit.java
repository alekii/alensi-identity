package io.alensi.identity.acl;

import java.math.BigDecimal;
import java.util.Objects;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;

/** A role's limit for a limited permission in one currency. A {@code null} amount is unlimited. */
@Embeddable
public class RoleLimit {

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "permission_id")
    private Permission permission;

    @Column(nullable = false, length = 3)
    private String currency;

    private BigDecimal maxAmount;

    protected RoleLimit() {
    }

    public RoleLimit(Permission permission, String currency, BigDecimal maxAmount) {
        this.permission = permission;
        this.currency = currency;
        this.maxAmount = maxAmount;
    }

    public Permission getPermission() {
        return permission;
    }

    public String getCurrency() {
        return currency;
    }

    public BigDecimal getMaxAmount() {
        return maxAmount;
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof RoleLimit that && Objects.equals(permission.getId(), that.permission.getId())
                && currency.equals(that.currency);
    }

    @Override
    public int hashCode() {
        return Objects.hash(permission.getId(), currency);
    }
}
