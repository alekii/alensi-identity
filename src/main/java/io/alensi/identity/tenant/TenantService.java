package io.alensi.identity.tenant;

import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import io.alensi.identity.acl.Target;
import io.alensi.identity.acl.TargetRepository;
import io.alensi.identity.acl.TargetType;
import io.alensi.identity.acl.TargetTypeRepository;
import io.alensi.identity.audit.AuditLog;
import io.alensi.identity.config.IdentityProperties;
import io.alensi.identity.user.AccessGuard;
import io.alensi.identity.user.KeycloakAdminClient;
import io.alensi.identity.user.UserAccount;
import io.alensi.identity.user.UserDirectory;
import io.alensi.identity.user.UserStatus;
import io.alensi.identity.web.BadRequestException;
import io.alensi.identity.web.ConflictException;
import io.alensi.identity.web.NotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Tenants and their members. Every tenant is a Keycloak organization in the shared realm; membership
 * here is mirrored to the organization so users can pick the tenant at login.
 */
@Service
@Transactional
public class TenantService {

    private final TenantRepository tenants;
    private final TenantMemberRepository members;
    private final TargetRepository targets;
    private final TargetTypeRepository targetTypes;
    private final UserDirectory directory;
    private final KeycloakAdminClient keycloak;
    private final AccessGuard access;
    private final AuditLog audit;
    private final IdentityProperties properties;

    TenantService(TenantRepository tenants, TenantMemberRepository members, TargetRepository targets,
            TargetTypeRepository targetTypes, UserDirectory directory, KeycloakAdminClient keycloak, AccessGuard access,
            AuditLog audit, IdentityProperties properties) {
        this.tenants = tenants;
        this.members = members;
        this.targets = targets;
        this.targetTypes = targetTypes;
        this.directory = directory;
        this.keycloak = keycloak;
        this.access = access;
        this.audit = audit;
        this.properties = properties;
    }

    /**
     * Onboards a tenant: its record, its root target (of a shared top-level type, e.g. {@code company})
     * and its Keycloak organization, which is created unless one with the alias exists.
     */
    public TenantView create(UserAccount actor, String code, String name, String rootType, String organization) {
        access.requirePlatform(actor);
        if (tenants.existsByCode(code) || targets.existsByCode(code)) {
            throw new ConflictException("Tenant or target '%s' already exists".formatted(code));
        }
        TargetType type = targetTypes.findByCodeAndTenantIsNull(rootType)
                .orElseThrow(() -> new NotFoundException("Target type '%s' not found".formatted(rootType)));
        if (type.getParent() != null) {
            throw new BadRequestException("Tenant roots need a top-level target type, not '%s'".formatted(rootType));
        }
        String alias = organization == null ? code.toLowerCase(Locale.ROOT) : organization;
        String realm = properties.keycloak().realm();
        Tenant tenant = tenants.save(new Tenant(code, name, realm, alias));
        Target root = targets.save(new Target(tenant, type, code, name));
        keycloak.findOrganizationId(alias).orElseGet(() -> keycloak.createOrganization(name, alias));
        audit.record(actor.getId(), tenant, "tenant.created", code, "organization=%s/%s root=%s".formatted(realm, alias,
                root.getCode()));
        return TenantView.of(tenant, root);
    }

    @Transactional(readOnly = true)
    public List<TenantView> visible(UserAccount caller) {
        Set<String> visible = access.visibleTenants(caller);
        return tenants.findAll().stream()
                .filter(tenant -> visible == null || visible.contains(tenant.getCode()))
                .map(tenant -> TenantView.of(tenant, root(tenant)))
                .sorted((a, b) -> a.code().compareTo(b.code()))
                .toList();
    }

    @Transactional(readOnly = true)
    public List<MemberView> members(UserAccount caller, String tenantCode) {
        Tenant tenant = tenant(tenantCode);
        access.requireTenantAdmin(caller, tenant);
        return members.findByTenant(tenant).stream().map(MemberView::of).toList();
    }

    public MemberView addMember(UserAccount actor, String tenantCode, String username) {
        Tenant tenant = tenant(tenantCode);
        access.requireTenantAdmin(actor, tenant);
        return MemberView.of(ensureMember(actor, tenant, directory.findByUsername(username)));
    }

    /** Makes the user a member if they are not one already. Used when granting them access. */
    public TenantMember ensureMember(UserAccount actor, Tenant tenant, UserAccount user) {
        return members.findByTenantAndUser(tenant, user).orElseGet(() -> {
            TenantMember member = members.save(new TenantMember(tenant, user));
            keycloak.addOrganizationMember(organizationId(tenant), user.getId());
            audit.record(actor.getId(), tenant, "tenant.member-added", user.getUsername(), null);
            return member;
        });
    }

    /** Suspends, reactivates or sets the expiry of a membership. Other tenants are unaffected. */
    public MemberView updateMember(UserAccount actor, String tenantCode, String username, UserStatus status,
            Instant expiresAt) {
        Tenant tenant = tenant(tenantCode);
        UserAccount user = directory.findByUsername(username);
        access.requireMembershipManagement(actor, user, tenant);
        TenantMember member = member(tenant, user);
        member.update(status, expiresAt);
        audit.record(actor.getId(), tenant, "tenant.member-updated", username,
                "status=%s expiresAt=%s".formatted(status, expiresAt));
        return MemberView.of(member);
    }

    /** Removes the membership, and with it every grant the user holds in the tenant. */
    public void removeMember(UserAccount actor, String tenantCode, String username) {
        Tenant tenant = tenant(tenantCode);
        access.requireTenantAdmin(actor, tenant);
        UserAccount user = directory.findByUsername(username);
        if (actor.getId().equals(user.getId())) {
            throw new BadRequestException("You cannot remove yourself");
        }
        members.delete(member(tenant, user));
        members.flush();
        keycloak.removeOrganizationMember(organizationId(tenant), user.getId());
        audit.record(actor.getId(), tenant, "tenant.member-removed", username, null);
    }

    @Transactional(readOnly = true)
    public Tenant tenant(String code) {
        return tenants.findByCode(code).orElseThrow(() -> new NotFoundException("Tenant '%s' not found".formatted(code)));
    }

    private TenantMember member(Tenant tenant, UserAccount user) {
        return members.findByTenantAndUser(tenant, user).orElseThrow(() -> new NotFoundException(
                "'%s' is not a member of '%s'".formatted(user.getUsername(), tenant.getCode())));
    }

    private Target root(Tenant tenant) {
        return targets.findByTenantAndParentIsNull(tenant).orElseThrow();
    }

    private String organizationId(Tenant tenant) {
        return keycloak.findOrganizationId(tenant.getKeycloakOrganization())
                .orElseThrow(() -> new IllegalStateException(
                        "Keycloak organization '%s' not found".formatted(tenant.getKeycloakOrganization())));
    }

    public record TenantView(String code, String name, String rootTarget, String keycloakRealm,
            String keycloakOrganization) {

        static TenantView of(Tenant tenant, Target root) {
            return new TenantView(tenant.getCode(), tenant.getName(), root.getCode(), tenant.getKeycloakRealm(),
                    tenant.getKeycloakOrganization());
        }
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
