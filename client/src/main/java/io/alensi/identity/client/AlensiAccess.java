package io.alensi.identity.client;

import java.math.BigDecimal;
import java.util.List;
import java.util.Objects;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * Permission checks for the current request, available as the bean {@code alensiAccess}:
 *
 * <pre>{@code
 * access.require("claims.view", claim.branchCode());                       // one record
 * TargetScope scope = access.scope("claims.view");                         // list queries
 * Decision d = access.decide("claims.approve", branch, amount, "KES");     // limited permissions
 * @PreAuthorize("@alensiAccess.can('claims.approve', #branch)")            // declaratively
 * }</pre>
 *
 * <p>Uses the caller's own token (so identity answers exactly for them) and the request's tenant:
 * the token's organization, or the {@code X-Alensi-Tenant} header, which is forwarded. Each user's
 * permission map is cached for {@code alensi.identity.client.cache-ttl}; limit decisions are always
 * live. Fails closed: if identity cannot answer, {@link AlensiIdentityException} propagates; if it
 * refuses (e.g. a tenant the caller is not a member of), {@code AccessDeniedException}.
 */
public class AlensiAccess {

    private final AlensiIdentityClient client;
    private final Cache<Key, PermissionMap> permissions;
    private final Cache<Key, IdentityContext> contexts;

    public AlensiAccess(AlensiIdentityClient client, AlensiIdentityProperties properties) {
        this.client = client;
        this.permissions = Caffeine.newBuilder()
                .expireAfterWrite(properties.cacheTtl())
                .maximumSize(properties.cacheMaxSize())
                .build();
        this.contexts = Caffeine.newBuilder()
                .expireAfterWrite(properties.cacheTtl())
                .maximumSize(properties.cacheMaxSize())
                .build();
    }

    /** Holds the permission on at least one target. */
    public boolean can(String permission) {
        return permissions().allowsAnywhere(permission);
    }

    /** Holds the permission on the target (directly, through an ancestor, or everywhere). */
    public boolean can(String permission, String target) {
        return permissions().allows(permission, target);
    }

    public void require(String permission, String target) {
        if (!can(permission, target)) {
            throw new AccessDeniedException("Missing '%s' on '%s'".formatted(permission, target));
        }
    }

    /** Where the caller holds the permission, for filtering queries. */
    public TargetScope scope(String permission) {
        return permissions().scope(permission);
    }

    /** Live check of a limited permission for an amount; see {@link Decision#limits()} to escalate. */
    public Decision decide(String permission, String target, BigDecimal amount, String currency) {
        Caller caller = caller();
        return client.decide(caller.token(), caller.tenantHeader(), permission, target, amount, currency);
    }

    /** The tenant code this request acts in, or null if the caller works in several and chose none. */
    public String tenant() {
        return context().tenant();
    }

    public IdentityContext context() {
        Caller caller = caller();
        return contexts.get(caller.key(), key -> client.context(caller.token(), caller.tenantHeader()));
    }

    /** Forgets the current caller's cached permissions, e.g. right after changing their access. */
    public void evictCurrentUser() {
        Key key = caller().key();
        permissions.invalidate(key);
        contexts.invalidate(key);
    }

    private PermissionMap permissions() {
        Caller caller = caller();
        return permissions.get(caller.key(), key -> client.permissions(caller.token(), caller.tenantHeader()));
    }

    private Caller caller() {
        if (!(SecurityContextHolder.getContext().getAuthentication() instanceof JwtAuthenticationToken jwt)) {
            throw new AuthenticationCredentialsNotFoundException("No bearer token for an alensi-identity check");
        }
        String tenantHeader = RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes
                ? header(attributes.getRequest())
                : null;
        List<String> organizations = jwt.getToken().hasClaim("organization")
                ? jwt.getToken().getClaimAsStringList("organization")
                : List.of();
        return new Caller(jwt.getToken().getTokenValue(),
                new Key(jwt.getToken().getSubject(), String.join(",", organizations), tenantHeader));
    }

    private static String header(HttpServletRequest request) {
        return request.getHeader(AlensiIdentityClient.TENANT_HEADER);
    }

    /** Same person in another tenant (organization or header) is a different cache entry. */
    record Key(String subject, String organizations, String tenantHeader) {

        Key {
            Objects.requireNonNull(subject);
        }
    }

    private record Caller(String token, Key key) {

        String tenantHeader() {
            return key.tenantHeader();
        }
    }
}
