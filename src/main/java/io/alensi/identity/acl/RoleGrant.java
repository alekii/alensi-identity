package io.alensi.identity.acl;

import java.time.Instant;
import java.util.UUID;

import io.alensi.identity.user.UserAccount;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import org.hibernate.annotations.CreationTimestamp;

/**
 * Gives a user a role on a target and all of its descendants. A {@code null} target is the
 * wildcard ({@code *}): the role applies on every target.
 */
@Entity
@Table(name = "role_grants")
public class RoleGrant {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id")
    private UserAccount user;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "role_id")
    private Role role;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "target_id")
    private Target target;

    private UUID grantedBy;

    @CreationTimestamp
    private Instant createdAt;

    protected RoleGrant() {
    }

    public RoleGrant(UserAccount user, Role role, Target target, UUID grantedBy) {
        this.user = user;
        this.role = role;
        this.target = target;
        this.grantedBy = grantedBy;
    }

    public boolean isWildcard() {
        return target == null;
    }

    public Long getId() {
        return id;
    }

    public UserAccount getUser() {
        return user;
    }

    public Role getRole() {
        return role;
    }

    public Target getTarget() {
        return target;
    }

    public UUID getGrantedBy() {
        return grantedBy;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
