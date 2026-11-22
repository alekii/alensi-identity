package io.alensi.identity.acl;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import io.alensi.identity.tenant.Tenant;
import org.hibernate.annotations.CreationTimestamp;

/** Something permissions are scoped to (a country, a shop, a merchant...). Targets form a tree. */
@Entity
@Table(name = "targets")
public class Target {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "type_id")
    private TargetType type;

    @Column(nullable = false, unique = true)
    private String code;

    @Column(nullable = false)
    private String name;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "parent_id")
    private Target parent;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "tenant_id")
    private Tenant tenant;

    @CreationTimestamp
    private Instant createdAt;

    protected Target() {
    }

    /** A tenant's root target. */
    public Target(Tenant tenant, TargetType type, String code, String name) {
        this.tenant = tenant;
        this.type = type;
        this.code = code;
        this.name = name;
    }

    /** A target below {@code parent}, in the same tenant. */
    public Target(TargetType type, String code, String name, Target parent) {
        this(parent.getTenant(), type, code, name);
        this.parent = parent;
    }

    public Tenant getTenant() {
        return tenant;
    }

    public Long getId() {
        return id;
    }

    public TargetType getType() {
        return type;
    }

    public String getCode() {
        return code;
    }

    public String getName() {
        return name;
    }

    public Target getParent() {
        return parent;
    }
}
