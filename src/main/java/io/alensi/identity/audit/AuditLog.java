package io.alensi.identity.audit;

import java.util.UUID;

import io.alensi.identity.tenant.Tenant;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Records security-relevant changes made through this service. Authentication events (logins,
 * MFA, failures) are recorded by Keycloak's event store.
 */
@Component
public class AuditLog {

    private final AuditEventRepository events;

    AuditLog(AuditEventRepository events) {
        this.events = events;
    }

    /** Joins the caller's transaction so the audit row commits or rolls back with the change. */
    @Transactional(propagation = Propagation.MANDATORY)
    public void record(UUID actorId, String action, String subject, String details) {
        record(actorId, null, action, subject, details);
    }

    /** An event belonging to a tenant's audit trail. */
    @Transactional(propagation = Propagation.MANDATORY)
    public void record(UUID actorId, Tenant tenant, String action, String subject, String details) {
        events.save(new AuditEvent(actorId, tenant == null ? null : tenant.getId(), action, subject, details));
    }
}
