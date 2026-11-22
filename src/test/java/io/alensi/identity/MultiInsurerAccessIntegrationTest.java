package io.alensi.identity;

import static org.hamcrest.Matchers.contains;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
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
    private static final KeycloakUser HOC = user("hellen");         // Jubilee Kenya head of claims
    private static final KeycloakUser SAM = user("sam");            // Jubilee agent, promoted to Jubilee's senior-agent
    private static final KeycloakUser BRIAN = user("brian");        // agent for both Jubilee and Madison
    // Jubilee's own management chain in its Mt Kenya area
    private static final KeycloakUser ARTHUR = user("arthur");      // area manager
    private static final KeycloakUser BELLA = user("bella");        // agency manager
    private static final KeycloakUser SID = user("sid");            // sales manager
    private static final KeycloakUser LUCY = user("lucy");          // unit lead
    private static final KeycloakUser AGGIE = user("aggie");        // agent

    private static boolean seeded;

    @Autowired
    MockMvc mvc;

    @MockitoBean
    KeycloakAdminClient keycloak;

    @BeforeEach
    void setUp() throws Exception {
        for (KeycloakUser user : List.of(PLATFORM, JUB_ADMIN, MAD_ADMIN, CENTRAL, MARY, TINA, ANN, THIKA, MOMBASA, HOC, SAM, BRIAN,
                ARTHUR, BELLA, SID, LUCY, AGGIE)) {
            given(keycloak.findById(user.id())).willReturn(Optional.of(user));
            given(keycloak.findByUsername(user.username())).willReturn(Optional.of(user));
        }
        given(keycloak.findOrganizationId(org.mockito.ArgumentMatchers.anyString())).willReturn(Optional.of("org-id"));
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
            ok(send(PLATFORM, post("/api/applications/alensi-insure/permissions"), "{\"code\": \"%s\", \"limited\": %s}"
                    .formatted(permission, permission.equals("claims.approve"))));
        }
        // Agent ranks: agent < team-lead < branch-manager.
        role("alensi-insure", "agent", "policies.view", "policies.sell");
        role("alensi-insure", "team-lead", "policies.view", "policies.sell", "team.reports");
        role("alensi-insure", "branch-manager", "policies.view", "claims.view", "claims.approve", "team.reports", "branch.reports");
        limits(PLATFORM, "branch-manager", null, """
                {"permission": "claims.approve", "currency": "KES", "maxAmount": 1000000}""");
        role("alensi-insure", "head-of-claims", "claims.view", "claims.approve");
        limits(PLATFORM, "head-of-claims", null, """
                {"permission": "claims.approve", "currency": "KES", "maxAmount": null}""");
        // An extra admin level so team leads can onboard agents into their own team.
        role("alensi-identity", "team-admin", "identity.users.manage", "identity.users.read", "identity.permissions.read");

        assignable("alensi-identity", "company-admin", "alensi-identity/regional-admin", "alensi-identity/branch-admin",
                "alensi-identity/team-admin", "alensi-insure/branch-manager", "alensi-insure/team-lead", "alensi-insure/agent",
                "alensi-insure/head-of-claims");
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
        // Platform onboards the insurers as tenants and hands each to its company admin.
        ok(send(PLATFORM, post("/api/tenants"), """
                {"code": "JUB", "name": "Jubilee Insurance", "rootType": "company"}"""));
        ok(send(PLATFORM, post("/api/tenants"), """
                {"code": "MAD", "name": "Madison General", "rootType": "company"}"""));
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
        grant(JUB_ADMIN, HOC, "alensi-insure", "head-of-claims", "JUB-KE");

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
        denied(send(JUB_ADMIN, post("/api/tenants"), """
                {"code": "ACME", "name": "Acme", "rootType": "company"}"""));
        send(PLATFORM, post("/api/targets"), """
                {"code": "ACME", "name": "Acme", "type": "company"}""").andExpect(status().isBadRequest());
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
    void membershipChangesNeedScopeOverEveryGrantInTheTenant() throws Exception {
        denied(send(CENTRAL, put("/api/tenants/JUB/members/ann"), suspend()));
        denied(send(TINA, put("/api/tenants/JUB/members/mary"), suspend()));
        denied(send(MARY, put("/api/tenants/JUB/members/mary"), suspend()));
        denied(send(JUB_ADMIN, put("/api/users/username/ann/access"), suspend())); // whole-account: platform only
        ok(send(MARY, put("/api/tenants/JUB/members/ann"), suspend()));
        allowed(MARY, "ann", "policies.sell", "JUB-KE-NRB-NWS-T1", false);
        ok(send(MARY, put("/api/tenants/JUB/members/ann"), """
                {"status": "ACTIVE"}"""));
    }

    // ---- Management chains configured as data ----

    @Test
    void tenantsConfigureTheirOwnManagementChains() throws Exception {
        // Jubilee adds an "area" level under its regions, with its own agency and sales-team levels below.
        tenantType("area", "region");
        tenantType("agency", "area");
        tenantType("sales-team", "agency");
        target(JUB_ADMIN, "JUB-KE-CEN-MTK", "area", "JUB-KE-CEN");
        target(JUB_ADMIN, "JUB-KE-CEN-MTK-NYR", "agency", "JUB-KE-CEN-MTK");
        target(JUB_ADMIN, "JUB-KE-CEN-MTK-NYR-S1", "sales-team", "JUB-KE-CEN-MTK-NYR");
        // Madison neither sees nor can use Jubilee's types.
        call(MAD_ADMIN, get("/api/target-types")).andExpect(jsonPath("$[?(@.code == 'area')]").isEmpty());
        send(MAD_ADMIN, post("/api/targets"), """
                {"code": "MAD-KE-CST-X", "name": "x", "type": "area", "parent": "MAD-KE-CST"}""")
                .andExpect(status().isNotFound());

        // area manager → agency manager → sales manager → unit lead → agent
        for (String[] role : List.of(new String[] { "unit-lead", "agent" }, new String[] { "sales-manager", "unit-lead" },
                new String[] { "agency-manager", "sales-manager" }, new String[] { "area-manager", "agency-manager" })) {
            ok(send(JUB_ADMIN, post("/api/applications/alensi-insure/roles"),
                    "{\"code\": \"%s\", \"name\": \"%s\", \"tenant\": \"JUB\", \"permissions\": [\"policies.view\", \"team.reports\"]}"
                            .formatted(role[0], role[0])));
            send(JUB_ADMIN, put("/api/applications/alensi-insure/roles/%s/assignable-roles?tenant=JUB".formatted(role[0])),
                    "{\"roles\": [{\"application\": \"alensi-insure\", \"role\": \"%s\"}]}".formatted(role[1]))
                    .andExpect(status().isOk());
        }
        grant(JUB_ADMIN, ARTHUR, "alensi-insure", "area-manager", "JUB-KE-CEN-MTK");
        grant(ARTHUR, BELLA, "alensi-insure", "agency-manager", "JUB-KE-CEN-MTK-NYR");
        grant(BELLA, SID, "alensi-insure", "sales-manager", "JUB-KE-CEN-MTK-NYR");
        grant(SID, LUCY, "alensi-insure", "unit-lead", "JUB-KE-CEN-MTK-NYR-S1");
        grant(LUCY, AGGIE, "alensi-insure", "agent", "JUB-KE-CEN-MTK-NYR-S1");

        // Each level can do whatever the levels below it can, inside its subtree, but never create
        // peers or superiors.
        ok(send(ARTHUR, post("/api/users/sam/grants"), grantBody("alensi-insure", "agent", "JUB-KE-CEN-MTK-NYR-S1")));
        ok(send(BELLA, post("/api/users/sam/grants"), grantBody("alensi-insure", "unit-lead", "JUB-KE-CEN-MTK-NYR-S1")));
        denied(send(LUCY, post("/api/users/aggie/grants"), grantBody("alensi-insure", "unit-lead", "JUB-KE-CEN-MTK-NYR-S1")));
        denied(send(SID, post("/api/users/lucy/grants"), grantBody("alensi-insure", "agency-manager", "JUB-KE-CEN-MTK-NYR")));
        denied(send(SID, post("/api/users/lucy/grants"), grantBody("alensi-insure", "sales-manager", "JUB-KE-CEN-MTK-NYR")));
        denied(send(ARTHUR, post("/api/users/bella/grants"), grantBody("alensi-insure", "area-manager", "JUB-KE-CEN-MTK")));
        denied(send(BELLA, post("/api/users/tom/grants"), grantBody("alensi-insure", "sales-manager", "JUB-KE-CEN-THK")));
        denied(send(ARTHUR, post("/api/users/tom/grants"), grantBody("alensi-insure", "agent", "JUB-KE-CEN-THK")));
        denied(send(AGGIE, post("/api/users/sam/grants"), grantBody("alensi-insure", "agent", "JUB-KE-CEN-MTK-NYR-S1")));
        // Chains must stay a hierarchy: a loop would let a unit lead reach their own superiors.
        send(JUB_ADMIN, put("/api/applications/alensi-insure/roles/unit-lead/assignable-roles?tenant=JUB"), """
                {"roles": [{"application": "alensi-insure", "role": "agent"},
                           {"application": "alensi-insure", "role": "area-manager", "tenant": "JUB"}]}""")
                .andExpect(status().isBadRequest());
        send(JUB_ADMIN, put("/api/applications/alensi-insure/roles/unit-lead/assignable-roles?tenant=JUB"), """
                {"roles": [{"application": "alensi-insure", "role": "unit-lead", "tenant": "JUB"}]}""")
                .andExpect(status().isBadRequest());

        // Managers see their people's access without any identity permission, and can suspend them in this tenant.
        call(SID, get("/api/users/aggie/grants")).andExpect(jsonPath("$[0].role").value("agent"));
        denied(call(LUCY, get("/api/users/sid/applications/alensi-insure/permissions")));   // not upwards
        denied(call(LUCY, get("/api/users/admin/applications/alensi-identity/permissions"))); // nor at the platform
        ok(send(LUCY, put("/api/tenants/JUB/members/aggie"), suspend()));
        ok(send(LUCY, put("/api/tenants/JUB/members/aggie"), """
                {"status": "ACTIVE"}"""));
        // Revoking follows the same rule: any level above may revoke, the person themselves may not.
        long aggieGrant = grantId(call(SID, get("/api/users/aggie/grants")));
        denied(call(AGGIE, delete("/api/users/aggie/grants/" + aggieGrant)));
        ok(call(SID, delete("/api/users/aggie/grants/" + aggieGrant)));
    }

    // ---- Staff onboarding ----

    @Test
    void managersOnboardStaffIntoTheirScope() throws Exception {
        UUID ninaId = UUID.randomUUID();
        KeycloakUser nina = new KeycloakUser(ninaId, "nina@jubilee.example", "nina@jubilee.example", "Nina", "Achieng",
                true, List.of("UPDATE_PASSWORD"));
        given(keycloak.findByEmail("nina@jubilee.example")).willReturn(Optional.empty());
        given(keycloak.createUser(eq("nina@jubilee.example"), eq("Nina"), eq("Achieng"), eq("+254711000111"), anyList()))
                .willReturn(nina);
        given(keycloak.findById(ninaId)).willReturn(Optional.of(nina));

        // Everything is authorized before anything is created in Keycloak.
        denied(send(MARY, post("/api/tenants/JUB/staff"), staff("nina@jubilee.example", "agent", "JUB-KE-CEN-THK")));
        denied(send(MARY, post("/api/tenants/JUB/staff"), """
                {"email": "nina@jubilee.example", "firstName": "Nina", "lastName": "Achieng"}"""));
        send(MARY, post("/api/tenants/JUB/staff"), staff("nina@jubilee.example", "agent", "MAD-KE-CST-MSA"))
                .andExpect(status().isBadRequest());
        verify(keycloak, never()).createUser(any(), any(), any(), any(), any());

        // A branch manager onboards an agent into their team: account, membership, grant, invite.
        send(MARY, post("/api/tenants/JUB/staff"), staff("nina@jubilee.example", "agent", "JUB-KE-NRB-NWS-T1"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.newAccount").value(true))
                .andExpect(jsonPath("$.invited").value(true))
                .andExpect(jsonPath("$.grants[0].role").value("agent"));
        verify(keycloak).createUser(eq("nina@jubilee.example"), eq("Nina"), eq("Achieng"), eq("+254711000111"),
                eq(List.of("UPDATE_PASSWORD", "VERIFY_EMAIL")));
        verify(keycloak).sendActionsEmail(eq(ninaId), eq(List.of("UPDATE_PASSWORD")), any(), eq("alensi-web"), any());
        call(JUB_ADMIN, get("/api/tenants/JUB/members"))
                .andExpect(jsonPath("$[?(@.username == 'nina@jubilee.example')]").isNotEmpty());
        call(MARY, get("/api/users/nina@jubilee.example/applications/alensi-insure/permissions/policies.sell/targets/JUB-KE-NRB-NWS-T1"))
                .andExpect(jsonPath("$.allowed").value(true));

        // Someone who already works for Madison keeps their one account: no new account, no invite.
        given(keycloak.findByEmail("musa@alensi.local")).willReturn(Optional.of(MOMBASA));
        send(MARY, post("/api/tenants/JUB/staff"), staff("musa@alensi.local", "agent", "JUB-KE-NRB-NWS-T1"))
                .andExpect(jsonPath("$.newAccount").value(false))
                .andExpect(jsonPath("$.invited").value(false));
        // Onboarding again is harmless.
        send(MARY, post("/api/tenants/JUB/staff"), staff("musa@alensi.local", "agent", "JUB-KE-NRB-NWS-T1"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.grants").isEmpty());
        verify(keycloak, never()).createUser(eq("musa@alensi.local"), any(), any(), any(), any());

        // Invites can be re-sent only while the account is not set up yet.
        call(MARY, post("/api/tenants/JUB/staff/nina@jubilee.example/invite")).andExpect(status().isAccepted());
        call(MARY, post("/api/tenants/JUB/staff/musa/invite")).andExpect(status().isConflict());

        given(keycloak.findByEmail("mary@alensi.local")).willReturn(Optional.of(MARY));
        send(MARY, post("/api/tenants/JUB/staff"), staff("mary@alensi.local", "agent", "JUB-KE-NRB-NWS-T1"))
                .andExpect(status().isBadRequest());
    }

    // ---- One person, two tenants ----

    @Test
    void personWorkingForTwoInsurersIsIsolatedPerTenant() throws Exception {
        grant(JUB_ADMIN, BRIAN, "alensi-insure", "agent", "JUB-KE-NRB-NWS");
        grant(MAD_ADMIN, BRIAN, "alensi-insure", "agent", "MAD-KE-CST-MSA");
        String sells = "/api/users/me/applications/alensi-insure/permissions/policies.sell/targets?compressed=true";

        // The tenant comes from the header (or the token's organization claim); each answers only for itself.
        call(BRIAN, get(sells).header("X-Alensi-Tenant", "JUB")).andExpect(jsonPath("$").value(contains("JUB-KE-NRB-NWS")));
        call(BRIAN, get(sells).header("X-Alensi-Tenant", "MAD")).andExpect(jsonPath("$").value(contains("MAD-KE-CST-MSA")));
        mvc.perform(get(sells).with(jwt().jwt(token -> token.subject(BRIAN.id().toString())
                        .claim("organization", List.of("mad")))))
                .andExpect(jsonPath("$").value(contains("MAD-KE-CST-MSA")));
        mvc.perform(get(sells).header("X-Alensi-Tenant", "JUB").with(jwt().jwt(token -> token
                        .subject(BRIAN.id().toString()).claim("organization", List.of("mad")))))
                .andExpect(status().isBadRequest());
        denied(call(THIKA, get(sells).header("X-Alensi-Tenant", "MAD")));

        // Each insurer sees only its own part of Brian.
        call(JUB_ADMIN, get("/api/users/brian/grants")).andExpect(jsonPath("$[*].tenant").value(contains("JUB")));
        call(MAD_ADMIN, get("/api/users/brian/grants")).andExpect(jsonPath("$[*].tenant").value(contains("MAD")));

        // Jubilee suspending Brian leaves his Madison work untouched.
        ok(send(JUB_ADMIN, put("/api/tenants/JUB/members/brian"), suspend()));
        call(BRIAN, get(sells).header("X-Alensi-Tenant", "MAD")).andExpect(jsonPath("$").value(contains("MAD-KE-CST-MSA")));
        denied(call(BRIAN, get(sells).header("X-Alensi-Tenant", "JUB")));
        call(BRIAN, get(sells)).andExpect(jsonPath("$").value(contains("MAD-KE-CST-MSA"))); // only active tenant
        ok(send(JUB_ADMIN, put("/api/tenants/JUB/members/brian"), """
                {"status": "ACTIVE"}"""));
    }

    @Test
    void tenantAdministrationStaysInsideTheTenant() throws Exception {
        call(MAD_ADMIN, get("/api/tenants")).andExpect(jsonPath("$[*].code").value(contains("MAD")));
        call(JUB_ADMIN, get("/api/tenants/JUB/members")).andExpect(jsonPath("$[?(@.username == 'mary')]").isNotEmpty());
        denied(call(MARY, get("/api/tenants/JUB/members")));            // branch admin is not a tenant admin
        denied(call(MAD_ADMIN, get("/api/tenants/JUB/members")));
        call(JUB_ADMIN, get("/api/tenants/JUB/audit-events?size=500"))
                .andExpect(jsonPath("$[?(@.action == 'tenant.created')]").isNotEmpty())
                .andExpect(jsonPath("$[?(@.subject == 'musa')]").isEmpty());
        denied(call(MAD_ADMIN, get("/api/tenants/JUB/audit-events")));
    }

    @Test
    void revocationFollowsTheSameRules() throws Exception {
        long grantId = grantId(call(MARY, get("/api/users/ann/grants")));
        denied(call(CENTRAL, delete("/api/users/ann/grants/" + grantId)));
        denied(call(TINA, delete("/api/users/tina/grants/" + grantId(call(TINA, get("/api/users/tina/grants"))))));
        ok(call(TINA, delete("/api/users/ann/grants/" + grantId)));
        grant(TINA, ANN, "alensi-insure", "agent", "JUB-KE-NRB-NWS-T1");
    }

    // ---- Per-insurer roles ----

    @Test
    void insurersDefineTheirOwnRolesWithTheSameCode() throws Exception {
        ok(send(JUB_ADMIN, post("/api/applications/alensi-insure/roles"), """
                {"code": "senior-agent", "name": "Senior agent", "tenant": "JUB",
                 "permissions": ["policies.view", "policies.sell", "team.reports"]}"""));
        ok(send(MAD_ADMIN, post("/api/applications/alensi-insure/roles"), """
                {"code": "senior-agent", "name": "Senior sales executive", "tenant": "MAD",
                 "permissions": ["policies.view", "policies.sell"]}"""));

        // Each admin sees platform roles plus their own company's, never the other's.
        call(MAD_ADMIN, get("/api/applications/alensi-insure/roles"))
                .andExpect(jsonPath("$[?(@.code == 'senior-agent')].tenant").value(contains("MAD")));
        call(JUB_ADMIN, get("/api/targets")).andExpect(jsonPath("$[?(@.tenant == 'MAD')]").isEmpty());

        // The role code resolves to the target's tenant's role. Jubilee's admin promotes Sam; Madison's resolves its own.
        grant(TINA, SAM, "alensi-insure", "agent", "JUB-KE-NRB-NWS-T1");
        ok(send(JUB_ADMIN, post("/api/users/sam/grants"), grantBody("alensi-insure", "senior-agent", "JUB-KE-NRB-NWS-T1")));
        call(JUB_ADMIN, get("/api/users/sam/applications/alensi-insure/permissions/team.reports/targets/JUB-KE-NRB-NWS-T1"))
                .andExpect(jsonPath("$.allowed").value(true));
        allowed(SAM, "me", "team.reports", "JUB-KE-NRB-NWS-T1", true);
        ok(send(MAD_ADMIN, post("/api/users/musa/grants"), grantBody("alensi-insure", "senior-agent", "MAD-KE-CST-MSA")));
        allowed(MOMBASA, "me", "team.reports", "MAD-KE-CST-MSA", false);
    }

    @Test
    void companyRolesCannotEscalateOrCrossCompanies() throws Exception {
        // Platform-wide roles and platform-only permissions stay with the platform.
        denied(send(JUB_ADMIN, post("/api/applications/alensi-insure/roles"), """
                {"code": "jub-global", "name": "x", "permissions": ["claims.view"]}"""));
        send(JUB_ADMIN, post("/api/applications/alensi-identity/roles"), """
                {"code": "jub-super", "name": "x", "tenant": "JUB", "permissions": ["identity.platform.manage"]}""")
                .andExpect(status().isBadRequest());
        // No shadowing of platform roles, no roles for another company, no limits on platform roles.
        send(JUB_ADMIN, post("/api/applications/alensi-insure/roles"), """
                {"code": "branch-manager", "name": "x", "tenant": "JUB", "permissions": ["claims.view"]}""")
                .andExpect(status().isConflict());
        denied(send(JUB_ADMIN, post("/api/applications/alensi-insure/roles"), """
                {"code": "mad-thing", "name": "x", "tenant": "MAD", "permissions": ["claims.view"]}"""));
        denied(send(JUB_ADMIN, put("/api/applications/alensi-insure/roles/branch-manager/limits"), """
                {"limits": [{"permission": "claims.approve", "currency": "KES", "maxAmount": null}]}"""));
        // A company's own roles can only be granted inside the company, and only by its admins.
        ok(send(JUB_ADMIN, post("/api/applications/alensi-insure/roles"), """
                {"code": "jub-auditor", "name": "Auditor", "tenant": "JUB", "permissions": ["claims.view"]}"""));
        send(MAD_ADMIN, post("/api/users/musa/grants"), grantBody("alensi-insure", "jub-auditor", "MAD-KE-CST-MSA"))
                .andExpect(status().isNotFound());
        denied(send(CENTRAL, post("/api/users/tom/grants"), grantBody("alensi-insure", "jub-auditor", "JUB-KE-CEN-THK")));
        send(MAD_ADMIN, put("/api/applications/alensi-insure/roles/jub-auditor/assignable-roles?tenant=JUB"), """
                {"roles": []}""").andExpect(status().isForbidden());
    }

    // ---- Approval limits ----

    @Test
    void approvalLimitsDecideWhenToEscalate() throws Exception {
        String approve = "/api/users/%s/applications/alensi-insure/permissions/claims.approve/targets/%s";
        call(MARY, get(approve.formatted("me", "JUB-KE-NRB-NWS") + "?amount=750000&currency=KES"))
                .andExpect(jsonPath("$.allowed").value(true))
                .andExpect(jsonPath("$.limits[0].currency").value("KES"))
                .andExpect(jsonPath("$.limits[0].maxAmount").value(1000000));
        call(MARY, get(approve.formatted("me", "JUB-KE-NRB-NWS") + "?amount=3000000&currency=KES"))
                .andExpect(jsonPath("$.allowed").value(false));
        call(MARY, get(approve.formatted("me", "JUB-KE-NRB-NWS") + "?amount=1000&currency=UGX"))
                .andExpect(jsonPath("$.allowed").value(false));
        // Head of claims (on JUB-KE) is unlimited in KES across all Kenyan branches.
        call(HOC, get(approve.formatted("me", "JUB-KE-CEN-THK") + "?amount=3000000&currency=KES"))
                .andExpect(jsonPath("$.allowed").value(true))
                .andExpect(jsonPath("$.limits[0].maxAmount").doesNotExist());
        // Agents hold no approval authority; non-limited permissions report no limits.
        call(ANN, get(approve.formatted("me", "JUB-KE-NRB-NWS-T1") + "?amount=1&currency=KES"))
                .andExpect(jsonPath("$.allowed").value(false));
        call(ANN, get("/api/users/me/applications/alensi-insure/permissions/policies.sell/targets/JUB-KE-NRB-NWS-T1"))
                .andExpect(jsonPath("$.limits").doesNotExist());
    }

    @Test
    void insurersSetTheirOwnLimits() throws Exception {
        ok(send(JUB_ADMIN, post("/api/applications/alensi-insure/roles"), """
                {"code": "claims-officer", "name": "Claims officer", "tenant": "JUB",
                 "permissions": ["claims.view", "claims.approve"],
                 "limits": [{"permission": "claims.approve", "currency": "KES", "maxAmount": 250000}]}"""));
        ok(send(JUB_ADMIN, post("/api/users/carol/grants"), grantBody("alensi-insure", "claims-officer", "JUB-KE-CEN")));
        String check = "/api/users/me/applications/alensi-insure/permissions/claims.approve/targets/JUB-KE-CEN-THK?amount=300000&currency=KES";
        call(CENTRAL, get(check)).andExpect(jsonPath("$.allowed").value(false));
        ok(send(JUB_ADMIN, put("/api/applications/alensi-insure/roles/claims-officer/limits?tenant=JUB"), """
                {"limits": [{"permission": "claims.approve", "currency": "KES", "maxAmount": 500000}]}"""));
        call(CENTRAL, get(check)).andExpect(jsonPath("$.allowed").value(true));
        send(JUB_ADMIN, put("/api/applications/alensi-insure/roles/claims-officer/limits?tenant=JUB"), """
                {"limits": [{"permission": "claims.view", "currency": "KES", "maxAmount": 1}]}""")
                .andExpect(status().isBadRequest());
    }

    private static String staff(String email, String role, String target) {
        return """
                {"email": "%s", "firstName": "Nina", "lastName": "Achieng", "phoneNumber": "+254711000111",
                 "grants": [{"application": "alensi-insure", "role": "%s", "target": "%s"}]}""".formatted(email, role, target);
    }

    private void tenantType(String code, String parent) throws Exception {
        ok(send(JUB_ADMIN, post("/api/target-types"),
                "{\"code\": \"%s\", \"name\": \"%s\", \"parent\": \"%s\", \"tenant\": \"JUB\"}".formatted(code, code, parent)));
    }

    private void limits(KeycloakUser actor, String role, String tenant, String limitJson) throws Exception {
        send(actor, put("/api/applications/alensi-insure/roles/%s/limits%s".formatted(role, tenant == null ? "" : "?tenant=" + tenant)),
                "{\"limits\": [%s]}".formatted(limitJson)).andExpect(status().isOk());
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
