package io.alensi.identity.acl;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import io.alensi.identity.audit.AuditEvent;
import io.alensi.identity.audit.AuditEventRepository;
import io.alensi.identity.user.UserAccount;
import org.springframework.data.domain.PageRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/audit-events")
class AuditController {

    private final AuditEventRepository events;
    private final AccessGuard access;

    AuditController(AuditEventRepository events, AccessGuard access) {
        this.events = events;
        this.access = access;
    }

    @GetMapping
    List<AuditEventResponse> list(UserAccount caller, @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size) {
        access.requireGlobal(caller, AccessGuard.AUDIT_READ);
        return events.findAllByOrderByOccurredAtDescIdDesc(PageRequest.of(page, Math.min(size, 200))).stream()
                .map(AuditEventResponse::of)
                .toList();
    }

    record AuditEventResponse(Long id, Instant occurredAt, UUID actorId, String action, String subject, String details) {

        static AuditEventResponse of(AuditEvent event) {
            return new AuditEventResponse(event.getId(), event.getOccurredAt(), event.getActorId(), event.getAction(),
                    event.getSubject(), event.getDetails());
        }
    }
}
