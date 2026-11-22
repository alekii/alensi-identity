package io.alensi.identity.user;

import org.springframework.core.MethodParameter;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

/** Injects the calling {@link UserAccount} into controller methods. */
@Component
public class CurrentUserArgumentResolver implements HandlerMethodArgumentResolver {

    private static final String ATTRIBUTE = CurrentUserArgumentResolver.class.getName() + ".caller";

    private final UserDirectory directory;

    CurrentUserArgumentResolver(UserDirectory directory) {
        this.directory = directory;
    }

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return parameter.getParameterType().equals(UserAccount.class);
    }

    @Override
    public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer mavContainer,
            NativeWebRequest webRequest, WebDataBinderFactory binderFactory) {
        return resolve(webRequest);
    }

    /** The caller, resolved once per request. */
    public UserAccount resolve(NativeWebRequest webRequest) {
        if (webRequest.getAttribute(ATTRIBUTE, RequestAttributes.SCOPE_REQUEST) instanceof UserAccount cached) {
            return cached;
        }
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !(authentication.getPrincipal() instanceof Jwt jwt)) {
            throw new AuthenticationCredentialsNotFoundException("No bearer token");
        }
        UserAccount caller = directory.resolveCaller(jwt);
        webRequest.setAttribute(ATTRIBUTE, caller, RequestAttributes.SCOPE_REQUEST);
        return caller;
    }
}
