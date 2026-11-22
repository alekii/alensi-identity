package io.alensi.identity.client;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.web.client.RestClient;

/** Active when {@code alensi.identity.client.base-url} is set. */
@AutoConfiguration
@ConditionalOnProperty(prefix = "alensi.identity.client", name = "base-url")
@EnableConfigurationProperties(AlensiIdentityProperties.class)
public class AlensiIdentityAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    AlensiIdentityClient alensiIdentityClient(ObjectProvider<RestClient.Builder> builders,
            AlensiIdentityProperties properties) {
        return new AlensiIdentityClient(builders.getIfAvailable(RestClient::builder), properties);
    }

    @Bean(name = "alensiAccess")
    @ConditionalOnMissingBean
    AlensiAccess alensiAccess(AlensiIdentityClient client, AlensiIdentityProperties properties) {
        return new AlensiAccess(client, properties);
    }
}
