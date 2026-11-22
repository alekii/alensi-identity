package io.alensi.identity.acl;

import io.alensi.identity.tenant.Tenant;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

@Entity
@Table(name = "target_types")
public class TargetType {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String code;

    @Column(nullable = false)
    private String name;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "parent_id")
    private TargetType parent;

    /** The tenant that defined this type, or {@code null} for a type shared by all tenants. */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "tenant_id")
    private Tenant tenant;

    protected TargetType() {
    }

    public TargetType(String code, String name, TargetType parent, Tenant tenant) {
        this.code = code;
        this.name = name;
        this.parent = parent;
        this.tenant = tenant;
    }

    public Tenant getTenant() {
        return tenant;
    }

    /** Usable in the tenant: shared, or defined by it. */
    public boolean isAvailableIn(Tenant candidate) {
        return tenant == null || tenant.getId().equals(candidate.getId());
    }

    public Long getId() {
        return id;
    }

    public String getCode() {
        return code;
    }

    public String getName() {
        return name;
    }

    public TargetType getParent() {
        return parent;
    }
}
