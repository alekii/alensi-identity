package io.alensi.identity.client;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

class PermissionMapTest {

    private final PermissionMap map = new PermissionMap(Map.of(
            "branch", Map.of("JUB-NBO", Set.of("claims.view", "claims.approve")),
            "team", Map.of("JUB-NBO-T1", Set.of("claims.view"))));

    @Test
    void answersPerTarget() {
        assertThat(map.allows("claims.view", "JUB-NBO-T1")).isTrue();
        assertThat(map.allows("claims.approve", "JUB-NBO-T1")).isFalse();
        assertThat(map.allows("claims.view", "JUB-MSA")).isFalse();
        assertThat(map.allowsAnywhere("claims.approve")).isTrue();
        assertThat(map.allowsAnywhere("claims.settle")).isFalse();
    }

    @Test
    void scopesForQueries() {
        assertThat(map.scope("claims.view").targets()).containsExactlyInAnyOrder("JUB-NBO", "JUB-NBO-T1");
        assertThat(map.scope("claims.settle").isEmpty()).isTrue();
        TargetScope everywhere = new PermissionMap(Map.of("*", Map.of("*", Set.of("claims.view")))).scope("claims.view");
        assertThat(everywhere.all()).isTrue();
        assertThat(everywhere.includes("ANY")).isTrue();
    }
}
