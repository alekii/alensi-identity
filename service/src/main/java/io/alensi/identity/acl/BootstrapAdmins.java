package io.alensi.identity.acl;

import io.alensi.identity.audit.AuditLog;
import io.alensi.identity.config.IdentityProperties;
import io.alensi.identity.user.UserAccountRepository;
import io.alensi.identity.user.UserProvisioned;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

/**
 * Grants {@code alensi-identity/platform-admin} on all targets to usernames listed in
 * {@code alensi.identity.bootstrap-admins} when they are first provisioned. Synchronous, in the
 * provisioning transaction, so the request that provisioned them already has the grant.
 */
@Component
class BootstrapAdmins {

    private final IdentityProperties properties;
    private final ApplicationRepository applications;
    private final RoleRepository roles;
    private final RoleGrantRepository grants;
    private final UserAccountRepository users;
    private final AuditLog audit;

    BootstrapAdmins(IdentityProperties properties, ApplicationRepository applications, RoleRepository roles,
            RoleGrantRepository grants, UserAccountRepository users, AuditLog audit) {
        this.properties = properties;
        this.applications = applications;
        this.roles = roles;
        this.grants = grants;
        this.users = users;
        this.audit = audit;
    }

    @EventListener
    void on(UserProvisioned event) {
        if (!properties.bootstrapAdmins().contains(event.username())) {
            return;
        }
        var user = users.getReferenceById(event.userId());
        var application = applications.findByCode(AccessGuard.APPLICATION).orElseThrow();
        var admin = roles.findByApplicationAndCodeAndTenantIsNull(application, "platform-admin").orElseThrow();
        if (!grants.existsByUserAndRoleAndTargetIsNull(user, admin)) {
            grants.save(new RoleGrant(user, admin, null, null));
            audit.record(null, "grant.created", event.username(), "bootstrap: alensi-identity/platform-admin on *");
        }
    }
}
