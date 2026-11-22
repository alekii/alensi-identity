package io.alensi.identity.audit;

import java.util.UUID;

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
        record(actorId, (Long) null, action, subject, details);
    }

    /** An event belonging to a tenant's audit trail ({@code tenantId} may be null for platform events). */
    @Transactional(propagation = Propagation.MANDATORY)
    public void record(UUID actorId, Long tenantId, String action, String subject, String details) {
        events.save(new AuditEvent(actorId, tenantId, action, subject, details));
    }
}
