package io.alensi.identity;

import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasItems;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import io.alensi.identity.keycloak.KeycloakAdminClient;
import io.alensi.identity.keycloak.KeycloakUser;
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

/** Applies the real catalog/alensi-insure.json and checks the resulting access model. */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
class CatalogIntegrationTest {

    @Container
    @ServiceConnection
    static PostgreSQLContainer postgres = new PostgreSQLContainer("postgres:17");

    private static final Path MANIFEST = Path.of("../catalog/alensi-insure.json");

    private static final KeycloakUser PLATFORM = user("admin");
    private static final KeycloakUser JUB_ADMIN = user("jub.it");
    private static final KeycloakUser RITA = user("rita");     // regional manager, Nairobi region
    private static final KeycloakUser BEN = user("ben");       // branch manager
    private static final KeycloakUser TOM = user("tom");       // team lead / agent

    private static boolean applied;

    @Autowired
    MockMvc mvc;

    @MockitoBean
    KeycloakAdminClient keycloak;

    @BeforeEach
    void setUp() throws Exception {
        for (KeycloakUser user : List.of(PLATFORM, JUB_ADMIN, RITA, BEN, TOM)) {
            given(keycloak.findById(user.id())).willReturn(Optional.of(user));
            given(keycloak.findByUsername(user.username())).willReturn(Optional.of(user));
        }
        given(keycloak.findOrganizationId(anyString())).willReturn(Optional.of("org-id"));
        if (!applied) {
            send(PLATFORM, put("/api/applications/alensi-insure/catalog"), Files.readString(MANIFEST))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$").value(hasItems("application created", "role branch-manager created",
                            "permission claims.approve created (limited)")));
            send(PLATFORM, post("/api/tenants"), """
                    {"code": "JUB", "name": "Jubilee", "rootType": "company"}""").andExpect(status().isCreated());
            target("JUB-KE", "country", "JUB");
            target("JUB-KE-NRB", "region", "JUB-KE");
            target("JUB-KE-NRB-NWS", "branch", "JUB-KE-NRB");
            target("JUB-KE-NRB-NWS-T1", "team", "JUB-KE-NRB-NWS");
            grant(PLATFORM, JUB_ADMIN, "alensi-identity", "company-admin", "JUB");
            applied = true;
        }
    }

    @Test
    void applyingTheSameManifestAgainChangesNothing() throws Exception {
        send(PLATFORM, put("/api/applications/alensi-insure/catalog"), Files.readString(MANIFEST))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isEmpty());
    }

    @Test
    void onlyThePlatformAppliesCatalogsAndUnsafeChangesAreRefused() throws Exception {
        send(JUB_ADMIN, put("/api/applications/alensi-insure/catalog"), Files.readString(MANIFEST))
                .andExpect(status().isForbidden());
        String unlimited = Files.readString(MANIFEST)
                .replace("{ \"code\": \"claims.approve\", \"description\": \"Approve claims; limited by claim amount\", \"limited\": true }",
                        "{ \"code\": \"claims.approve\", \"description\": \"Approve claims\" }");
        send(PLATFORM, put("/api/applications/alensi-insure/catalog"), unlimited).andExpect(status().isConflict());
        send(PLATFORM, put("/api/applications/alensi-insure/catalog"), """
                {"name": "Alensi Insure", "roles": [{"code": "x", "name": "x", "permissions": ["claims.teleport"]}]}""")
                .andExpect(status().isBadRequest());
    }

    @Test
    void defaultRolesFormManagementChainsWithLimits() throws Exception {
        call(PLATFORM, get("/api/applications/alensi-insure/roles"))
                .andExpect(jsonPath("$[?(@.code == 'branch-manager')].assignableRoles[*]")
                        .value(hasItems("alensi-insure/team-lead", "alensi-insure/customer-service")))
                .andExpect(jsonPath("$[?(@.code == 'head-of-claims')].limits[*].permission").value(hasItem("claims.settle")));
        call(PLATFORM, get("/api/applications/alensi-identity/roles"))
                .andExpect(jsonPath("$[?(@.code == 'company-admin')].assignableRoles[*]").value(hasItem("alensi-insure/head-of-claims")));

        // Company admin appoints a regional manager; the regional manager can staff the whole chain below.
        grant(JUB_ADMIN, RITA, "alensi-insure", "regional-manager", "JUB-KE-NRB");
        grant(RITA, BEN, "alensi-insure", "branch-manager", "JUB-KE-NRB-NWS");
        grant(RITA, TOM, "alensi-insure", "team-lead", "JUB-KE-NRB-NWS-T1");
        send(BEN, post("/api/users/tom/grants"), grantBody("alensi-insure", "regional-manager", "JUB-KE-NRB-NWS"))
                .andExpect(status().isForbidden());

        // Approval limits: KES 3M is within the regional manager's 5M, above the branch manager's 1M.
        String approve = "/api/users/me/applications/alensi-insure/permissions/claims.approve/targets/JUB-KE-NRB-NWS?amount=3000000&currency=KES";
        call(RITA, get(approve)).andExpect(jsonPath("$.allowed").value(true));
        call(BEN, get(approve)).andExpect(jsonPath("$.allowed").value(false))
                .andExpect(jsonPath("$.limits[0].maxAmount").value(1000000));
        call(TOM, get(approve)).andExpect(jsonPath("$.allowed").value(false));
    }

    @Test
    void contractPermissionsAreOnTheirRolesAndFlowIsGrantedByThePlatformOnly() throws Exception {
        call(PLATFORM, get("/api/applications/alensi-insure/roles"))
                .andExpect(jsonPath("$[?(@.code == 'head-of-claims')].permissions[*]")
                        .value(hasItems("claims.approve-senior", "documents.sensitive.view", "knowledge.manage")))
                .andExpect(jsonPath("$[?(@.code == 'claims-officer')].permissions[*]").value(not(hasItem("claims.approve-senior"))))
                .andExpect(jsonPath("$[?(@.code == 'agent')].permissions[*]").value(not(hasItem("documents.sensitive.view"))))
                .andExpect(jsonPath("$[?(@.code == 'flow-service')].permissions[*]").value(hasItem("workflows.act")));

        // Acting on behalf of users is not something a tenant admin hands out.
        send(JUB_ADMIN, post("/api/users/tom/grants"), grantBody("alensi-insure", "flow-service", "JUB"))
                .andExpect(status().isForbidden());
    }

    private void target(String code, String type, String parent) throws Exception {
        send(PLATFORM, post("/api/targets"), "{\"code\": \"%s\", \"name\": \"%s\", \"type\": \"%s\", \"parent\": \"%s\"}"
                .formatted(code, code, type, parent)).andExpect(status().isCreated());
    }

    private void grant(KeycloakUser actor, KeycloakUser user, String application, String role, String target) throws Exception {
        send(actor, post("/api/users/%s/grants".formatted(user.username())), grantBody(application, role, target))
                .andExpect(status().isCreated());
    }

    private static String grantBody(String application, String role, String target) {
        return "{\"application\": \"%s\", \"role\": \"%s\", \"target\": \"%s\"}".formatted(application, role, target);
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
