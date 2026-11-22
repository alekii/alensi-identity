package io.alensi.identity.tenant;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.CreationTimestamp;

/**
 * An organization served by the platform (an insurer). Maps to a Keycloak organization in a realm,
 * owns a subtree of targets rooted at a single target, and has members.
 */
@Entity
@Table(name = "tenants")
public class Tenant {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String code;

    @Column(nullable = false)
    private String name;

    @Column(nullable = false)
    private String keycloakRealm;

    /** The Keycloak organization alias; appears in the token's {@code organization} claim. */
    @Column(nullable = false)
    private String keycloakOrganization;

    @CreationTimestamp
    private Instant createdAt;

    protected Tenant() {
    }

    public Tenant(String code, String name, String keycloakRealm, String keycloakOrganization) {
        this.code = code;
        this.name = name;
        this.keycloakRealm = keycloakRealm;
        this.keycloakOrganization = keycloakOrganization;
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

    public String getKeycloakRealm() {
        return keycloakRealm;
    }

    public String getKeycloakOrganization() {
        return keycloakOrganization;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
