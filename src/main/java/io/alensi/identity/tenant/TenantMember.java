package io.alensi.identity.tenant;

import java.io.Serializable;
import java.time.Instant;
import java.util.UUID;

import io.alensi.identity.user.UserAccount;
import io.alensi.identity.user.UserStatus;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import org.hibernate.annotations.CreationTimestamp;

/**
 * A person's membership of a tenant. Status and expiry are per membership, so one insurer
 * suspending someone does not affect their work for another.
 */
@Entity
@Table(name = "tenant_members")
@IdClass(TenantMember.Key.class)
public class TenantMember {

    @Id
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "tenant_id")
    private Tenant tenant;

    @Id
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private UserAccount user;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private UserStatus status = UserStatus.ACTIVE;

    private Instant expiresAt;

    @CreationTimestamp
    private Instant createdAt;

    protected TenantMember() {
    }

    public TenantMember(Tenant tenant, UserAccount user) {
        this.tenant = tenant;
        this.user = user;
    }

    public boolean isActiveAt(Instant now) {
        return status == UserStatus.ACTIVE && (expiresAt == null || expiresAt.isAfter(now));
    }

    public void update(UserStatus status, Instant expiresAt) {
        this.status = status;
        this.expiresAt = expiresAt;
    }

    public Tenant getTenant() {
        return tenant;
    }

    public UserAccount getUser() {
        return user;
    }

    public UserStatus getStatus() {
        return status;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public record Key(Long tenant, UUID user) implements Serializable {

        public Key() {
            this(null, null);
        }
    }
}
