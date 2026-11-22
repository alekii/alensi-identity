package io.alensi.identity.acl;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;

class PermissionEvaluatorTest {

    // KE (country) > NBO (city) > NBO-WEST (shop);  UG (country) > KLA (city)
    private static final TargetNode KE = new TargetNode(1, "KE", "Kenya", "country", null);
    private static final TargetNode NBO = new TargetNode(2, "NBO", "Nairobi", "city", 1L);
    private static final TargetNode NBO_WEST = new TargetNode(3, "NBO-WEST", "Westlands", "shop", 2L);
    private static final TargetNode UG = new TargetNode(4, "UG", "Uganda", "country", null);
    private static final TargetNode KLA = new TargetNode(5, "KLA", "Kampala", "city", 4L);

    private static final TargetTree TREE = new TargetTree(List.of(KE, NBO, NBO_WEST, UG, KLA));

    @Test
    void grantOnTargetCoversItsDescendantsOnly() {
        var evaluator = new PermissionEvaluator(TREE, List.of(new EffectiveGrant(NBO, Set.of("orders.view"))));

        assertThat(evaluator.hasPermission("orders.view", NBO)).isTrue();
        assertThat(evaluator.hasPermission("orders.view", NBO_WEST)).isTrue();
        assertThat(evaluator.hasPermission("orders.view", KE)).isFalse();
        assertThat(evaluator.hasPermission("orders.view", KLA)).isFalse();
        assertThat(evaluator.hasPermission("orders.refund", NBO)).isFalse();
    }

    @Test
    void wildcardGrantCoversEveryTarget() {
        var evaluator = new PermissionEvaluator(TREE, List.of(new EffectiveGrant(null, Set.of("orders.view"))));

        assertThat(evaluator.hasPermission("orders.view", KLA)).isTrue();
        assertThat(evaluator.targetsWith("orders.view", false)).containsExactly("*");
        assertThat(evaluator.permissions(true, null)).containsOnlyKeys("*");
        assertThat(evaluator.targets("country")).containsExactly(KE, UG);
    }

    @Test
    void compressedMapKeepsGrantsWhereTheyWereMade() {
        var evaluator = new PermissionEvaluator(TREE, List.of(
                new EffectiveGrant(KE, Set.of("orders.view")),
                new EffectiveGrant(NBO_WEST, Set.of("orders.refund"))));

        var compressed = evaluator.permissions(true, null);
        assertThat(compressed).containsOnlyKeys("country", "shop");
        assertThat(compressed.get("country").get("KE")).containsExactly("orders.view");

        var expanded = evaluator.permissions(false, null);
        assertThat(expanded.get("city").get("NBO")).containsExactly("orders.view");
        assertThat(expanded.get("shop").get("NBO-WEST")).containsExactly("orders.refund", "orders.view");

        assertThat(evaluator.permissions(false, "city")).containsOnlyKeys("city");
    }

    @Test
    void permissionsOnTargetIncludeInheritedAndWildcardGrants() {
        var evaluator = new PermissionEvaluator(TREE, List.of(
                new EffectiveGrant(KE, Set.of("orders.view")),
                new EffectiveGrant(null, Set.of("reports.view")),
                new EffectiveGrant(UG, Set.of("orders.refund"))));

        assertThat(evaluator.permissionsOn(NBO_WEST))
                .containsOnlyKeys("shop")
                .extractingByKey("shop")
                .satisfies(byCode -> assertThat(byCode.get("NBO-WEST")).containsExactly("orders.view", "reports.view"));
    }

    @Test
    void targetsWithPermissionAreExpandedUnlessCompressed() {
        var evaluator = new PermissionEvaluator(TREE, List.of(new EffectiveGrant(NBO, Set.of("orders.view"))));

        assertThat(evaluator.targetsWith("orders.view", false)).containsExactly("NBO", "NBO-WEST");
        assertThat(evaluator.targetsWith("orders.view", true)).containsExactly("NBO");
        assertThat(evaluator.targetsWith("orders.refund", false)).isEmpty();
    }
}
