package io.alensi.identity.config;

import java.util.List;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Registers the argument resolvers that modules contribute as beans (e.g. the calling user, the
 * request's tenant), without this module depending on them.
 */
@Configuration(proxyBeanMethods = false)
class WebConfig implements WebMvcConfigurer {

    private final List<HandlerMethodArgumentResolver> resolvers;

    WebConfig(List<HandlerMethodArgumentResolver> resolvers) {
        this.resolvers = resolvers;
    }

    @Override
    public void addArgumentResolvers(List<HandlerMethodArgumentResolver> registry) {
        registry.addAll(resolvers);
    }
}
