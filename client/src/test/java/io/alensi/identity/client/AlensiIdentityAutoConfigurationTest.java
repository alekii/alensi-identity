package io.alensi.identity.client;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

class AlensiIdentityAutoConfigurationTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(AlensiIdentityAutoConfiguration.class));

    @Test
    void staysOffUntilConfigured() {
        runner.run(context -> assertThat(context).doesNotHaveBean(AlensiAccess.class));
    }

    @Test
    void providesAlensiAccessWhenConfigured() {
        runner.withPropertyValues("alensi.identity.client.base-url=http://localhost:8090",
                        "alensi.identity.client.application=alensi-insure", "alensi.identity.client.cache-ttl=10s")
                .run(context -> {
                    assertThat(context).hasSingleBean(AlensiIdentityClient.class);
                    assertThat(context).hasBean("alensiAccess");
                    assertThat(context.getBean(AlensiIdentityProperties.class).cacheTtl()).hasSeconds(10);
                });
    }

    @Test
    void failsFastWithoutAnApplication() {
        runner.withPropertyValues("alensi.identity.client.base-url=http://localhost:8090")
                .run(context -> assertThat(context).hasFailed());
    }
}
