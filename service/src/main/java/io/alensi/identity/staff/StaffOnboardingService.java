package io.alensi.identity.staff;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

import io.alensi.identity.acl.AclAdminService;
import io.alensi.identity.acl.AclViews;
import io.alensi.identity.audit.AuditLog;
import io.alensi.identity.config.IdentityProperties;
import io.alensi.identity.tenant.Tenant;
import io.alensi.identity.tenant.TenantService;
import io.alensi.identity.user.AccessGuard;
import io.alensi.identity.user.KeycloakAdminClient;
import io.alensi.identity.user.KeycloakUser;
import io.alensi.identity.user.UserAccount;
import io.alensi.identity.user.UserDirectory;
import io.alensi.identity.web.BadRequestException;
import io.alensi.identity.web.ConflictException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Brings a person into a tenant in one step: their Keycloak account (created, or reused if they
 * already work for another tenant), membership, grants, and an invite email to set a password.
 *
 * <p>Everything is authorized before anything is created: a manager can onboard people only with
 * roles they may assign, on targets inside their scope. Onboarding without grants is for tenant
 * admins. Sign-in then needs a second factor (authenticator app, SMS or email code; see the
 * Keycloak flows), and Sign in with Google links to the account by email.
 */
@Service
public class StaffOnboardingService {

    private final KeycloakAdminClient keycloak;
    private final UserDirectory directory;
    private final TenantService tenants;
    private final AclAdminService acl;
    private final AccessGuard access;
    private final AuditLog audit;
    private final IdentityProperties properties;

    StaffOnboardingService(KeycloakAdminClient keycloak, UserDirectory directory, TenantService tenants,
            AclAdminService acl, AccessGuard access, AuditLog audit, IdentityProperties properties) {
        this.keycloak = keycloak;
        this.directory = directory;
        this.tenants = tenants;
        this.acl = acl;
        this.access = access;
        this.audit = audit;
        this.properties = properties;
    }

    @Transactional
    public Onboarded onboard(UserAccount actor, String tenantCode, NewStaff staff) {
        Tenant tenant = tenants.tenant(tenantCode);
        if (staff.grants().isEmpty()) {
            access.requireTenantAdmin(actor, tenant);
        }
        for (GrantRequest grant : staff.grants()) {
            acl.checkGrant(actor, tenant, grant.application(), grant.role(), grant.target());
        }
        String email = staff.email().trim().toLowerCase(Locale.ROOT);
        Optional<KeycloakUser> existing = keycloak.findByEmail(email);
        if (existing.isPresent() && existing.get().id().equals(actor.getId())) {
            throw new BadRequestException("You cannot onboard yourself");
        }
        KeycloakUser account = existing.orElseGet(() -> keycloak.createUser(email, staff.firstName(), staff.lastName(),
                staff.phoneNumber(), requiredActions(staff)));
        UserAccount user = directory.findOrProvision(account);
        tenants.ensureMember(actor, tenant, user);

        List<AclViews.GrantView> granted = new ArrayList<>();
        for (GrantRequest grant : staff.grants()) {
            // Re-onboarding someone with a grant they already hold is not an error.
            acl.grantIfAbsent(actor, user, grant.application(), grant.role(), grant.target()).ifPresent(granted::add);
        }
        boolean invited = existing.isEmpty() || account.isPendingSetup();
        if (invited) {
            invite(account);
        }
        audit.record(actor.getId(), tenant, "staff.onboarded", user.getUsername(),
                "newAccount=%s invited=%s grants=%d".formatted(existing.isEmpty(), invited, granted.size()));
        return new Onboarded(user.getUsername(), existing.isEmpty(), invited, granted);
    }

    /** Re-sends the invite to someone who has not set up their account yet (e.g. the link expired). */
    @Transactional
    public void resendInvite(UserAccount actor, String tenantCode, String username) {
        Tenant tenant = tenants.tenant(tenantCode);
        UserAccount user = directory.findByUsername(username);
        access.requireMembershipManagement(actor, user, tenant);
        KeycloakUser account = keycloak.findById(user.getId()).orElseThrow();
        if (!account.isPendingSetup()) {
            throw new ConflictException("'%s' has already set up their account".formatted(username));
        }
        invite(account);
        audit.record(actor.getId(), tenant, "staff.invite-resent", username, null);
    }

    private void invite(KeycloakUser account) {
        IdentityProperties.Onboarding onboarding = properties.onboarding();
        keycloak.sendActionsEmail(account.id(), account.requiredActions(), onboarding.inviteLifespan(),
                onboarding.clientId(), onboarding.redirectUri());
    }

    /**
     * Completed from the invite link. VERIFY_EMAIL is satisfied by that same click, so the address is
     * verified, which Sign in with Google relies on when it links to the account by email.
     */
    private static List<String> requiredActions(NewStaff staff) {
        return staff.requireAuthenticatorApp()
                ? List.of(KeycloakAdminClient.UPDATE_PASSWORD, KeycloakAdminClient.VERIFY_EMAIL, KeycloakAdminClient.CONFIGURE_TOTP)
                : List.of(KeycloakAdminClient.UPDATE_PASSWORD, KeycloakAdminClient.VERIFY_EMAIL);
    }

    public record NewStaff(String email, String firstName, String lastName, String phoneNumber,
            boolean requireAuthenticatorApp, List<GrantRequest> grants) {

        public NewStaff {
            grants = grants == null ? List.of() : List.copyOf(grants);
        }
    }

    public record GrantRequest(String application, String role, String target) {
    }

    /** {@code newAccount}: a Keycloak account was created; {@code invited}: an invite email was sent. */
    public record Onboarded(String username, boolean newAccount, boolean invited, List<AclViews.GrantView> grants) {
    }
}
