package io.alensi.identity.acl;

import java.util.HashSet;
import java.util.Set;

import io.alensi.identity.tenant.Tenant;
import jakarta.persistence.CollectionTable;
import jakarta.persistence.ElementCollection;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

/** A named bundle of an application's permissions. Users receive roles through {@link RoleGrant}s. */
@Entity
@Table(name = "roles")
public class Role {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "application_id")
    private Application application;

    @Column(nullable = false)
    private String code;

    @Column(nullable = false)
    private String name;

    /** The tenant that owns this role, or {@code null} for a role shared by all tenants. */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "tenant_id")
    private Tenant tenant;

    @ManyToMany
    @JoinTable(name = "role_permissions",
            joinColumns = @JoinColumn(name = "role_id"),
            inverseJoinColumns = @JoinColumn(name = "permission_id"))
    private Set<Permission> permissions = new HashSet<>();

    /** Roles that holders of this role may grant to others, within the target this role was granted on. */
    @ManyToMany
    @JoinTable(name = "role_assignable_roles",
            joinColumns = @JoinColumn(name = "role_id"),
            inverseJoinColumns = @JoinColumn(name = "assignable_role_id"))
    private Set<Role> assignableRoles = new HashSet<>();

    @ElementCollection
    @CollectionTable(name = "role_permission_limits", joinColumns = @JoinColumn(name = "role_id"))
    private Set<RoleLimit> limits = new HashSet<>();

    protected Role() {
    }

    public Role(Application application, String code, String name, Set<Permission> permissions, Tenant tenant) {
        this.application = application;
        this.code = code;
        this.name = name;
        this.permissions = new HashSet<>(permissions);
        this.tenant = tenant;
    }

    public boolean isShared() {
        return tenant == null;
    }

    public Long getId() {
        return id;
    }

    public Application getApplication() {
        return application;
    }

    public String getCode() {
        return code;
    }

    public String getName() {
        return name;
    }

    public Set<Permission> getPermissions() {
        return permissions;
    }

    public Tenant getTenant() {
        return tenant;
    }

    public Set<RoleLimit> getLimits() {
        return limits;
    }

    public void replaceLimits(Set<RoleLimit> newLimits) {
        limits.clear();
        limits.addAll(newLimits);
    }

    public Set<Role> getAssignableRoles() {
        return assignableRoles;
    }

    public void replaceAssignableRoles(Set<Role> roles) {
        assignableRoles.clear();
        assignableRoles.addAll(roles);
    }
}
