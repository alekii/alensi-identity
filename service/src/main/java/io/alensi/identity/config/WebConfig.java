package io.alensi.identity.config;

import java.util.List;

import io.alensi.identity.tenant.TenantContextArgumentResolver;
import io.alensi.identity.user.CurrentUserArgumentResolver;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration(proxyBeanMethods = false)
class WebConfig implements WebMvcConfigurer {

    private final CurrentUserArgumentResolver currentUserArgumentResolver;
    private final TenantContextArgumentResolver tenantContextArgumentResolver;

    WebConfig(CurrentUserArgumentResolver currentUserArgumentResolver,
            TenantContextArgumentResolver tenantContextArgumentResolver) {
        this.currentUserArgumentResolver = currentUserArgumentResolver;
        this.tenantContextArgumentResolver = tenantContextArgumentResolver;
    }

    @Override
    public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
        resolvers.add(currentUserArgumentResolver);
        resolvers.add(tenantContextArgumentResolver);
    }
}
