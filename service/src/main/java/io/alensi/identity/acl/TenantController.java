package io.alensi.identity.acl;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import io.alensi.identity.audit.AuditEvent;
import io.alensi.identity.audit.AuditEventRepository;
import io.alensi.identity.tenant.Tenant;
import io.alensi.identity.tenant.TenantService;
import io.alensi.identity.user.UserAccount;
import io.alensi.identity.user.UserDirectory;
import io.alensi.identity.user.UserStatus;
import io.alensi.identity.web.BadRequestException;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpStatus;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * Tenant onboarding (platform), membership and the tenant's audit trail (tenant admins: holders of
 * {@code identity.users.manage} on the tenant root). Authorizes, then delegates to the tenant module.
 */
@RestController
@RequestMapping("/api/tenants")
class TenantController {

    private final TenantService tenants;
    private final AclAdminService admin;
    private final UserDirectory directory;
    private final AuditEventRepository events;
    private final AccessGuard access;

    TenantController(TenantService tenants, AclAdminService admin, UserDirectory directory, AuditEventRepository events,
            AccessGuard access) {
        this.tenants = tenants;
        this.admin = admin;
        this.directory = directory;
        this.events = events;
        this.access = access;
    }

    @GetMapping
    @Transactional(readOnly = true)
    List<AclViews.TenantView> list(UserAccount caller) {
        Set<String> visible = access.visibleTenants(caller);
        return tenants.all().stream()
                .filter(tenant -> visible == null || visible.contains(tenant.getCode()))
                .map(tenant -> AclViews.TenantView.of(tenant, admin.root(tenant)))
                .sorted((a, b) -> a.code().compareTo(b.code()))
                .toList();
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    AclViews.TenantView create(UserAccount caller, @Valid @RequestBody NewTenant body) {
        return admin.createTenant(caller, body.code(), body.name(), body.rootType(), body.organization());
    }

    @GetMapping("/{tenant}/members")
    List<TenantService.MemberView> members(UserAccount caller, @PathVariable String tenant) {
        Tenant found = tenants.tenant(tenant);
        access.requireTenantAdmin(caller, found);
        return tenants.members(found);
    }

    @PostMapping("/{tenant}/members")
    @ResponseStatus(HttpStatus.CREATED)
    TenantService.MemberView addMember(UserAccount caller, @PathVariable String tenant,
            @Valid @RequestBody NewMember body) {
        Tenant found = tenants.tenant(tenant);
        access.requireTenantAdmin(caller, found);
        UserAccount user = directory.findByUsername(body.username());
        tenants.ensureMember(caller.getId(), found, user);
        return tenants.members(found).stream().filter(member -> member.username().equals(user.getUsername()))
                .findFirst().orElseThrow();
    }

    @PutMapping("/{tenant}/members/{username}")
    TenantService.MemberView updateMember(UserAccount caller, @PathVariable String tenant,
            @PathVariable String username, @Valid @RequestBody MembershipUpdate body) {
        Tenant found = tenants.tenant(tenant);
        UserAccount user = directory.findByUsername(username);
        access.requireMembershipManagement(caller, user, found);
        return tenants.updateMember(caller.getId(), found, user, body.status(), body.expiresAt());
    }

    @DeleteMapping("/{tenant}/members/{username}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    void removeMember(UserAccount caller, @PathVariable String tenant, @PathVariable String username) {
        Tenant found = tenants.tenant(tenant);
        access.requireTenantAdmin(caller, found);
        UserAccount user = directory.findByUsername(username);
        if (caller.getId().equals(user.getId())) {
            throw new BadRequestException("You cannot remove yourself");
        }
        tenants.removeMember(caller.getId(), found, user);
    }

    @GetMapping("/{tenant}/audit-events")
    List<AuditEventResponse> auditEvents(UserAccount caller, @PathVariable String tenant,
            @RequestParam(defaultValue = "0") int page, @RequestParam(defaultValue = "50") int size) {
        Tenant found = tenants.tenant(tenant);
        access.requireTenantAdmin(caller, found);
        return events.findByTenantIdOrderByOccurredAtDescIdDesc(found.getId(), PageRequest.of(page, Math.min(size, 200)))
                .stream()
                .map(AuditEventResponse::of)
                .toList();
    }

    /** {@code rootType} is a shared top-level target type, e.g. {@code company}. */
    record NewTenant(@NotBlank @Size(max = 64) @Pattern(regexp = "^[A-Z0-9][A-Z0-9-]*$") String code,
            @NotBlank @Size(max = 255) String name, @NotBlank String rootType,
            @Pattern(regexp = "^[a-z0-9][a-z0-9-]*$") String organization) {
    }

    record NewMember(@NotBlank String username) {
    }

    record MembershipUpdate(@NotNull UserStatus status, Instant expiresAt) {
    }

    record AuditEventResponse(Long id, Instant occurredAt, UUID actorId, String action, String subject, String details) {

        static AuditEventResponse of(AuditEvent event) {
            return new AuditEventResponse(event.getId(), event.getOccurredAt(), event.getActorId(), event.getAction(),
                    event.getSubject(), event.getDetails());
        }
    }
}
