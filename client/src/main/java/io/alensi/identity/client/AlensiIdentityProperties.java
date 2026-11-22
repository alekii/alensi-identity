package io.alensi.identity.client;

import java.net.URI;
import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * {@code alensi.identity.client.*}.
 *
 * @param baseUrl alensi-identity, e.g. {@code http://localhost:8090}
 * @param application this service's application code in the identity catalog, e.g. {@code alensi-insure}
 * @param cacheTtl how long a user's permissions are reused before asking identity again (default 30s).
 *        Bounds how long a revoked grant keeps working in this service.
 * @param cacheMaxSize most users' permission maps kept in memory (default 10000)
 */
@ConfigurationProperties("alensi.identity.client")
public record AlensiIdentityProperties(URI baseUrl, String application, Duration cacheTtl, Long cacheMaxSize) {

    public AlensiIdentityProperties {
        cacheTtl = cacheTtl == null ? Duration.ofSeconds(30) : cacheTtl;
        cacheMaxSize = cacheMaxSize == null ? 10_000L : cacheMaxSize;
    }
}
