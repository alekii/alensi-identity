package io.alensi.identity;

import static org.hamcrest.Matchers.contains;
import static org.mockito.BDDMockito.given;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import com.jayway.jsonpath.JsonPath;
import io.alensi.identity.user.KeycloakAdminClient;
import io.alensi.identity.user.KeycloakUser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

/**
 * alensi-insure as a shared platform. Two insurers, each its own subtree:
 *
 * <pre>
 * JUB Jubilee ── JUB-KE ─┬─ JUB-KE-NRB (Nairobi region) ── JUB-KE-NRB-NWS (Nairobi West branch) ── JUB-KE-NRB-NWS-T1 (team)
 *                        └─ JUB-KE-CEN (Central region) ── JUB-KE-CEN-THK (Thika branch)
 * MAD Madison ── MAD-KE ─── MAD-KE-CST (Coast region)  ── MAD-KE-CST-MSA (Mombasa branch)
 * </pre>
 *
 * Chain of command: platform admin → company admin → regional admin → branch admin → team admin.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
class MultiInsurerAccessIntegrationTest {

    @Container
    @ServiceConnection
    static PostgreSQLContainer postgres = new PostgreSQLContainer("postgres:17");

    private static final KeycloakUser PLATFORM = user("admin");     // Alensi operations (bootstrap)
    private static final KeycloakUser JUB_ADMIN = user("jub.it");   // Jubilee company admin
    private static final KeycloakUser MAD_ADMIN = user("mad.it");   // Madison company admin
    private static final KeycloakUser CENTRAL = user("carol");      // Jubilee Central regional admin
    private static final KeycloakUser MARY = user("mary");          // Jubilee Nairobi West branch manager
    private static final KeycloakUser TINA = user("tina");          // Nairobi West team lead (team 1)
    private static final KeycloakUser ANN = user("ann");            // agent in team 1
    private static final KeycloakUser THIKA = user("tom");          // Thika branch manager
    private static final KeycloakUser MOMBASA = user("musa");       // Madison Mombasa agent

    private static boolean seeded;

    @Autowired
    MockMvc mvc;

    @MockitoBean
    KeycloakAdminClient keycloak;

    @BeforeEach
    void setUp() throws Exception {
        for (KeycloakUser user : List.of(PLATFORM, JUB_ADMIN, MAD_ADMIN, CENTRAL, MARY, TINA, ANN, THIKA, MOMBASA)) {
            given(keycloak.findById(user.id())).willReturn(Optional.of(user));
            given(keycloak.findByUsername(user.username())).willReturn(Optional.of(user));
        }
        if (!seeded) {
            seed();
            seeded = true;
        }
    }

    /** Everything a platform admin sets up once, then delegation down the chain. */
    private void seed() throws Exception {
        ok(send(PLATFORM, post("/api/applications"), """
                {"code": "alensi-insure", "name": "Alensi Insure"}"""));
        for (String permission : List.of("policies.view", "policies.sell", "claims.view", "claims.approve",
                "team.reports", "branch.reports")) {
            ok(send(PLATFORM, post("/api/applications/alensi-insure/permissions"), "{\"code\": \"%s\"}".formatted(permission)));
        }
        // Agent ranks: agent < team-lead < branch-manager.
        role("alensi-insure", "agent", "policies.view", "policies.sell");
        role("alensi-insure", "team-lead", "policies.view", "policies.sell", "team.reports");
        role("alensi-insure", "branch-manager", "policies.view", "claims.view", "claims.approve", "team.reports", "branch.reports");
        // An extra admin level so team leads can onboard agents into their own team.
        role("alensi-identity", "team-admin", "identity.users.manage", "identity.users.read", "identity.permissions.read");

        assignable("alensi-identity", "company-admin", "alensi-identity/regional-admin", "alensi-identity/branch-admin",
                "alensi-identity/team-admin", "alensi-insure/branch-manager", "alensi-insure/team-lead", "alensi-insure/agent");
        assignable("alensi-identity", "regional-admin", "alensi-identity/branch-admin", "alensi-identity/team-admin",
                "alensi-insure/branch-manager", "alensi-insure/team-lead", "alensi-insure/agent");
        assignable("alensi-identity", "branch-admin", "alensi-identity/team-admin", "alensi-insure/team-lead",
                "alensi-insure/agent");
        assignable("alensi-identity", "team-admin", "alensi-insure/agent");

        for (String[] type : List.of(new String[] { "company", null }, new String[] { "country", "company" },
                new String[] { "region", "country" }, new String[] { "branch", "region" }, new String[] { "team", "branch" })) {
            ok(send(PLATFORM, post("/api/target-types"), type[1] == null
                    ? "{\"code\": \"%s\", \"name\": \"%s\"}".formatted(type[0], type[0])
                    : "{\"code\": \"%s\", \"name\": \"%s\", \"parent\": \"%s\"}".formatted(type[0], type[0], type[1])));
        }
        // Platform creates the companies and hands each to its company admin.
        target(PLATFORM, "JUB", "company", null);
        target(PLATFORM, "MAD", "company", null);
        grant(PLATFORM, JUB_ADMIN, "alensi-identity", "company-admin", "JUB");
        grant(PLATFORM, MAD_ADMIN, "alensi-identity", "company-admin", "MAD");

        // Company admins build their own structure.
        target(JUB_ADMIN, "JUB-KE", "country", "JUB");
        target(JUB_ADMIN, "JUB-KE-NRB", "region", "JUB-KE");
        target(JUB_ADMIN, "JUB-KE-CEN", "region", "JUB-KE");
        target(JUB_ADMIN, "JUB-KE-NRB-NWS", "branch", "JUB-KE-NRB");
        target(JUB_ADMIN, "JUB-KE-CEN-THK", "branch", "JUB-KE-CEN");
        target(MAD_ADMIN, "MAD-KE", "country", "MAD");
        target(MAD_ADMIN, "MAD-KE-CST", "region", "MAD-KE");
        target(MAD_ADMIN, "MAD-KE-CST-MSA", "branch", "MAD-KE-CST");

        grant(JUB_ADMIN, CENTRAL, "alensi-identity", "regional-admin", "JUB-KE-CEN");
        grant(JUB_ADMIN, MARY, "alensi-insure", "branch-manager", "JUB-KE-NRB-NWS");
        grant(JUB_ADMIN, MARY, "alensi-identity", "branch-admin", "JUB-KE-NRB-NWS");
        grant(CENTRAL, THIKA, "alensi-insure", "branch-manager", "JUB-KE-CEN-THK");
        grant(MAD_ADMIN, MOMBASA, "alensi-insure", "agent", "MAD-KE-CST-MSA");

        // The branch manager opens a team and appoints a team lead, who onboards an agent.
        target(MARY, "JUB-KE-NRB-NWS-T1", "team", "JUB-KE-NRB-NWS");
        grant(MARY, TINA, "alensi-insure", "team-lead", "JUB-KE-NRB-NWS-T1");
        grant(MARY, TINA, "alensi-identity", "team-admin", "JUB-KE-NRB-NWS-T1");
        grant(TINA, ANN, "alensi-insure", "agent", "JUB-KE-NRB-NWS-T1");
    }

    // ---- Data visibility (what alensi-insure filters on) ----

    @Test
    void branchManagerSeesOnlyTheirBranch() throws Exception {
        allowed(MARY, "me", "claims.view", "JUB-KE-NRB-NWS", true);
        allowed(MARY, "me", "claims.view", "JUB-KE-NRB-NWS-T1", true);
        allowed(MARY, "me", "claims.view", "JUB-KE-CEN-THK", false);
        allowed(MARY, "me", "claims.view", "MAD-KE-CST-MSA", false);
        call(MARY, get("/api/users/me/applications/alensi-insure/permissions/claims.view/targets?compressed=true"))
                .andExpect(jsonPath("$").value(contains("JUB-KE-NRB-NWS")));
    }

    @Test
    void agentRanksDifferInPermissionsNotScope() throws Exception {
        allowed(TINA, "me", "team.reports", "JUB-KE-NRB-NWS-T1", true);
        allowed(ANN, "me", "team.reports", "JUB-KE-NRB-NWS-T1", false);
        allowed(ANN, "me", "policies.sell", "JUB-KE-NRB-NWS-T1", true);
        allowed(TINA, "me", "policies.view", "JUB-KE-NRB-NWS", false); // team lead does not see the whole branch
    }

    // ---- Delegated user management ----

    @Test
    void eachLevelAssignsOnlyItsAssignableRolesInsideItsScope() throws Exception {
        // Branch admin cannot create another branch manager; regional admin can, but only in their region.
        denied(send(MARY, post("/api/users/tina/grants"), grantBody("alensi-insure", "branch-manager", "JUB-KE-NRB-NWS")));
        denied(send(CENTRAL, post("/api/users/tina/grants"), grantBody("alensi-insure", "branch-manager", "JUB-KE-NRB-NWS")));
        // Team admin onboards agents only, only into their team.
        denied(send(TINA, post("/api/users/ann/grants"), grantBody("alensi-insure", "team-lead", "JUB-KE-NRB-NWS-T1")));
        denied(send(TINA, post("/api/users/ann/grants"), grantBody("alensi-insure", "agent", "JUB-KE-NRB-NWS")));
        // Company admin cannot reach into another insurer, or create peers.
        denied(send(JUB_ADMIN, post("/api/users/musa/grants"), grantBody("alensi-insure", "agent", "MAD-KE-CST-MSA")));
        denied(send(JUB_ADMIN, post("/api/users/carol/grants"), grantBody("alensi-identity", "company-admin", "JUB")));
    }

    @Test
    void nobodyBelowPlatformCanEscalate() throws Exception {
        denied(send(MARY, post("/api/users/mary/grants"), grantBody("alensi-insure", "agent", "JUB-KE-NRB-NWS")));
        denied(send(MARY, post("/api/users/tina/grants"), """
                {"application": "alensi-identity", "role": "platform-admin"}"""));
        denied(send(JUB_ADMIN, post("/api/users/carol/grants"), """
                {"application": "alensi-insure", "role": "agent"}"""));
        denied(send(JUB_ADMIN, post("/api/applications"), """
                {"code": "rogue", "name": "Rogue"}"""));
        denied(send(JUB_ADMIN, put("/api/applications/alensi-identity/roles/branch-admin/assignable-roles"), """
                {"roles": [{"application": "alensi-identity", "role": "company-admin"}]}"""));
        denied(call(JUB_ADMIN, get("/api/audit-events")));
    }

    @Test
    void targetsAreCreatedOnlyInsideScope() throws Exception {
        denied(send(JUB_ADMIN, post("/api/targets"), """
                {"code": "ACME", "name": "Acme", "type": "company"}"""));
        denied(send(JUB_ADMIN, post("/api/targets"), """
                {"code": "MAD-KE-WST", "name": "Western", "type": "region", "parent": "MAD-KE"}"""));
        denied(send(CENTRAL, post("/api/targets"), """
                {"code": "JUB-KE-NRB-WLD", "name": "Westlands", "type": "branch", "parent": "JUB-KE-NRB"}"""));
        ok(send(CENTRAL, post("/api/targets"), """
                {"code": "JUB-KE-CEN-NYR", "name": "Nyeri", "type": "branch", "parent": "JUB-KE-CEN"}"""));
    }

    @Test
    void adminsSeeOnlyTheirPartOfOtherUsersAccess() throws Exception {
        // Mary sees Ann (in her branch); the Central admin and Madison do not.
        call(MARY, get("/api/users/ann/grants")).andExpect(status().isOk()).andExpect(jsonPath("$[0].role").value("agent"));
        denied(call(CENTRAL, get("/api/users/ann/grants")));
        denied(call(MAD_ADMIN, get("/api/users/ann/applications/alensi-insure/permissions")));
        // Mary may see Tina's team access but not ask about targets outside Nairobi West.
        allowed(MARY, "tina", "team.reports", "JUB-KE-NRB-NWS-T1", true);
        denied(call(MARY, get("/api/users/tina/applications/alensi-insure/permissions/team.reports/targets/JUB-KE-CEN-THK")));
        // The company admin sees everyone in Jubilee, clipped to Jubilee.
        call(JUB_ADMIN, get("/api/users/tom/applications/alensi-insure/permissions?compressed=true"))
                .andExpect(jsonPath("$.branch['JUB-KE-CEN-THK']").isArray());
    }

    @Test
    void accountChangesNeedScopeOverEveryGrant() throws Exception {
        denied(send(CENTRAL, put("/api/users/username/ann/access"), suspend()));
        denied(send(TINA, put("/api/users/username/mary/access"), suspend()));
        denied(send(MARY, put("/api/users/username/mary/access"), suspend()));
        ok(send(MARY, put("/api/users/username/ann/access"), suspend()));
        allowed(MARY, "ann", "policies.sell", "JUB-KE-NRB-NWS-T1", false);
        ok(send(MARY, put("/api/users/username/ann/access"), """
                {"status": "ACTIVE"}"""));
    }

    @Test
    void revocationFollowsTheSameRules() throws Exception {
        long grantId = grantId(call(MARY, get("/api/users/ann/grants")));
        denied(call(CENTRAL, delete("/api/users/ann/grants/" + grantId)));
        denied(call(TINA, delete("/api/users/tina/grants/" + grantId(call(TINA, get("/api/users/tina/grants"))))));
        ok(call(TINA, delete("/api/users/ann/grants/" + grantId)));
        grant(TINA, ANN, "alensi-insure", "agent", "JUB-KE-NRB-NWS-T1");
    }

    private void role(String application, String code, String... permissions) throws Exception {
        ok(send(PLATFORM, post("/api/applications/%s/roles".formatted(application)),
                "{\"code\": \"%s\", \"name\": \"%s\", \"permissions\": [%s]}".formatted(code, code, quoted(permissions))));
    }

    private void assignable(String application, String role, String... refs) throws Exception {
        String roles = String.join(", ", java.util.Arrays.stream(refs)
                .map(ref -> ref.split("/"))
                .map(ref -> "{\"application\": \"%s\", \"role\": \"%s\"}".formatted(ref[0], ref[1]))
                .toList());
        send(PLATFORM, put("/api/applications/%s/roles/%s/assignable-roles".formatted(application, role)),
                "{\"roles\": [%s]}".formatted(roles)).andExpect(status().isOk());
    }

    private void target(KeycloakUser actor, String code, String type, String parent) throws Exception {
        ok(send(actor, post("/api/targets"), parent == null
                ? "{\"code\": \"%s\", \"name\": \"%s\", \"type\": \"%s\"}".formatted(code, code, type)
                : "{\"code\": \"%s\", \"name\": \"%s\", \"type\": \"%s\", \"parent\": \"%s\"}".formatted(code, code, type, parent)));
    }

    private void grant(KeycloakUser actor, KeycloakUser user, String application, String role, String target) throws Exception {
        ok(send(actor, post("/api/users/%s/grants".formatted(user.username())), grantBody(application, role, target)));
    }

    private void allowed(KeycloakUser caller, String user, String permission, String target, boolean expected) throws Exception {
        call(caller, get("/api/users/%s/applications/alensi-insure/permissions/%s/targets/%s".formatted(user, permission, target)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.allowed").value(expected));
    }

    private static long grantId(ResultActions grants) throws Exception {
        String json = grants.andReturn().getResponse().getContentAsString();
        List<Number> ids = JsonPath.read(json, "$[?(@.application == 'alensi-insure')].id");
        return ids.get(0).longValue();
    }

    private static String grantBody(String application, String role, String target) {
        return "{\"application\": \"%s\", \"role\": \"%s\", \"target\": \"%s\"}".formatted(application, role, target);
    }

    private static String suspend() {
        return """
                {"status": "SUSPENDED"}""";
    }

    private static String quoted(String... values) {
        return String.join(", ", java.util.Arrays.stream(values).map(v -> "\"" + v + "\"").toList());
    }

    private static void ok(ResultActions result) throws Exception {
        int status = result.andReturn().getResponse().getStatus();
        if (status >= 300) {
            throw new AssertionError("Expected success but was " + status + ": "
                    + result.andReturn().getResponse().getContentAsString());
        }
    }

    private static void denied(ResultActions result) throws Exception {
        result.andExpect(status().isForbidden());
    }

    private ResultActions call(KeycloakUser user, MockHttpServletRequestBuilder request) throws Exception {
        return mvc.perform(request.with(jwt().jwt(token -> token.subject(user.id().toString()))));
    }

    private ResultActions send(KeycloakUser user, MockHttpServletRequestBuilder request, String body) throws Exception {
        return mvc.perform(request.with(jwt().jwt(token -> token.subject(user.id().toString())))
                .contentType(MediaType.APPLICATION_JSON).content(body));
    }

    private static KeycloakUser user(String username) {
        return new KeycloakUser(UUID.randomUUID(), username, username + "@alensi.local", username, null, true);
    }
}
