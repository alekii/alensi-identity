package io.alensi.identity.tenant;

import java.util.List;

import io.alensi.identity.acl.PermissionService;
import io.alensi.identity.config.IdentityProperties;
import io.alensi.identity.user.AccessGuard;
import io.alensi.identity.user.CurrentUserArgumentResolver;
import io.alensi.identity.user.UserAccount;
import io.alensi.identity.web.BadRequestException;
import io.alensi.identity.web.NotFoundException;
import org.springframework.core.MethodParameter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

/**
 * Resolves the {@link TenantContext}: the single organization in the token
 * ({@code scope=organization:<alias>}), else the {@value TenantContext#HEADER} header, else the
 * caller's only active membership. A chosen tenant must be one the caller is an active member of.
 */
@Component
public class TenantContextArgumentResolver implements HandlerMethodArgumentResolver {

    private static final String ORGANIZATION_CLAIM = "organization";

    private final CurrentUserArgumentResolver currentUser;
    private final TenantRepository tenants;
    private final PermissionService permissions;
    private final AccessGuard access;
    private final IdentityProperties properties;

    TenantContextArgumentResolver(CurrentUserArgumentResolver currentUser, TenantRepository tenants,
            PermissionService permissions, AccessGuard access, IdentityProperties properties) {
        this.currentUser = currentUser;
        this.tenants = tenants;
        this.permissions = permissions;
        this.access = access;
        this.properties = properties;
    }

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return parameter.getParameterType().equals(TenantContext.class);
    }

    @Override
    public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer mavContainer,
            NativeWebRequest webRequest, WebDataBinderFactory binderFactory) {
        UserAccount caller = currentUser.resolve(webRequest);
        Tenant fromToken = fromToken();
        String header = webRequest.getHeader(TenantContext.HEADER);
        Tenant fromHeader = header == null ? null : tenants.findByCode(header)
                .orElseThrow(() -> new NotFoundException("Tenant '%s' not found".formatted(header)));
        if (fromToken != null && fromHeader != null && !fromToken.getId().equals(fromHeader.getId())) {
            throw new BadRequestException("%s does not match the token's organization".formatted(TenantContext.HEADER));
        }
        Tenant chosen = fromToken != null ? fromToken : fromHeader;
        List<Tenant> memberships = permissions.activeMemberships(caller).stream().map(TenantMember::getTenant).toList();
        if (chosen == null) {
            return new TenantContext(memberships.size() == 1 ? memberships.getFirst() : null);
        }
        boolean member = memberships.stream().anyMatch(tenant -> tenant.getId().equals(chosen.getId()));
        if (!member && !access.isPlatformAdmin(caller)) {
            throw new AccessDeniedException("You are not an active member of '%s'".formatted(chosen.getCode()));
        }
        return new TenantContext(chosen);
    }

    private Tenant fromToken() {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !(authentication.getPrincipal() instanceof Jwt jwt)) {
            return null;
        }
        List<String> organizations = jwt.hasClaim(ORGANIZATION_CLAIM) ? jwt.getClaimAsStringList(ORGANIZATION_CLAIM) : List.of();
        if (organizations == null || organizations.size() != 1) {
            return null;
        }
        String alias = organizations.getFirst();
        return tenants.findByKeycloakRealmAndKeycloakOrganization(properties.keycloak().realm(), alias)
                .orElseThrow(() -> new NotFoundException("No tenant for organization '%s'".formatted(alias)));
    }
}
