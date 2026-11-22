package io.alensi.identity.tenant;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import io.alensi.identity.audit.AuditLog;
import io.alensi.identity.config.IdentityProperties;
import io.alensi.identity.keycloak.KeycloakAdminClient;
import io.alensi.identity.user.UserAccount;
import io.alensi.identity.user.UserStatus;
import io.alensi.identity.web.ConflictException;
import io.alensi.identity.web.NotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Tenants and their members. Every tenant is a Keycloak organization in the shared realm; membership
 * here is mirrored to the organization so users can pick the tenant at login.
 *
 * <p>Domain operations only: callers (the acl module) authorize before calling.
 */
@Service
@Transactional
public class TenantService {

    private final TenantRepository tenants;
    private final TenantMemberRepository members;
    private final KeycloakAdminClient keycloak;
    private final AuditLog audit;
    private final IdentityProperties properties;

    TenantService(TenantRepository tenants, TenantMemberRepository members, KeycloakAdminClient keycloak,
            AuditLog audit, IdentityProperties properties) {
        this.tenants = tenants;
        this.members = members;
        this.keycloak = keycloak;
        this.audit = audit;
        this.properties = properties;
    }

    /** Creates the tenant and its Keycloak organization, unless one with the alias exists already. */
    public Tenant create(UUID actorId, String code, String name, String organization) {
        if (tenants.existsByCode(code)) {
            throw new ConflictException("Tenant '%s' already exists".formatted(code));
        }
        String realm = properties.keycloak().realm();
        Tenant tenant = tenants.save(new Tenant(code, name, realm, organization));
        keycloak.findOrganizationId(organization).orElseGet(() -> keycloak.createOrganization(name, organization));
        audit.record(actorId, tenant.getId(), "tenant.created", code, "organization=%s/%s".formatted(realm, organization));
        return tenant;
    }

    @Transactional(readOnly = true)
    public List<Tenant> all() {
        return tenants.findAll();
    }

    @Transactional(readOnly = true)
    public List<MemberView> members(Tenant tenant) {
        return members.findByTenant(tenant).stream().map(MemberView::of).toList();
    }

    /** Makes the user a member if they are not one already. */
    public TenantMember ensureMember(UUID actorId, Tenant tenant, UserAccount user) {
        return members.findByTenantAndUser(tenant, user).orElseGet(() -> {
            TenantMember member = members.save(new TenantMember(tenant, user));
            keycloak.addOrganizationMember(organizationId(tenant), user.getId());
            audit.record(actorId, tenant.getId(), "tenant.member-added", user.getUsername(), null);
            return member;
        });
    }

    /** Suspends, reactivates or sets the expiry of a membership. Other tenants are unaffected. */
    public MemberView updateMember(UUID actorId, Tenant tenant, UserAccount user, UserStatus status, Instant expiresAt) {
        TenantMember member = member(tenant, user);
        member.update(status, expiresAt);
        audit.record(actorId, tenant.getId(), "tenant.member-updated", user.getUsername(),
                "status=%s expiresAt=%s".formatted(status, expiresAt));
        return MemberView.of(member);
    }

    /** Removes the membership, and with it every grant the user holds in the tenant. */
    public void removeMember(UUID actorId, Tenant tenant, UserAccount user) {
        members.delete(member(tenant, user));
        members.flush();
        keycloak.removeOrganizationMember(organizationId(tenant), user.getId());
        audit.record(actorId, tenant.getId(), "tenant.member-removed", user.getUsername(), null);
    }

    @Transactional(readOnly = true)
    public Tenant tenant(String code) {
        return tenants.findByCode(code).orElseThrow(() -> new NotFoundException("Tenant '%s' not found".formatted(code)));
    }

    private TenantMember member(Tenant tenant, UserAccount user) {
        return members.findByTenantAndUser(tenant, user).orElseThrow(() -> new NotFoundException(
                "'%s' is not a member of '%s'".formatted(user.getUsername(), tenant.getCode())));
    }

    private String organizationId(Tenant tenant) {
        return keycloak.findOrganizationId(tenant.getKeycloakOrganization())
                .orElseThrow(() -> new IllegalStateException(
                        "Keycloak organization '%s' not found".formatted(tenant.getKeycloakOrganization())));
    }

    public record MemberView(String username, String name, String email, UserStatus status, Instant expiresAt,
            Instant memberSince) {

        static MemberView of(TenantMember member) {
            UserAccount user = member.getUser();
            return new MemberView(user.getUsername(), user.getName(), user.getEmail(), member.getStatus(),
                    member.getExpiresAt(), member.getCreatedAt());
        }
    }
}
