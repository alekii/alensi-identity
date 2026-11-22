package io.alensi.identity.audit;

import java.time.Instant;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.CreationTimestamp;

@Entity
@Table(name = "audit_events")
public class AuditEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @CreationTimestamp
    private Instant occurredAt;

    private UUID actorId;

    @Column(nullable = false)
    private String action;

    @Column(nullable = false)
    private String subject;

    private String details;

    protected AuditEvent() {
    }

    AuditEvent(UUID actorId, String action, String subject, String details) {
        this.actorId = actorId;
        this.action = action;
        this.subject = subject;
        this.details = details;
    }

    public Long getId() {
        return id;
    }

    public Instant getOccurredAt() {
        return occurredAt;
    }

    public UUID getActorId() {
        return actorId;
    }

    public String getAction() {
        return action;
    }

    public String getSubject() {
        return subject;
    }

    public String getDetails() {
        return details;
    }
}
