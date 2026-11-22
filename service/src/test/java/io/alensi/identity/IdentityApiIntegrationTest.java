package io.alensi.identity;

import static org.mockito.BDDMockito.given;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Optional;
import java.util.UUID;

import io.alensi.identity.user.KeycloakAdminClient;
import io.alensi.identity.user.KeycloakUser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.JwtRequestPostProcessor;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

/** Full API flow against real Postgres. Tokens are stubbed; the Keycloak Admin API is mocked. */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
class IdentityApiIntegrationTest {

    @Container
    @ServiceConnection
    static PostgreSQLContainer postgres = new PostgreSQLContainer("postgres:17");

    private static final KeycloakUser ADMIN = new KeycloakUser(UUID.randomUUID(), "admin", "admin@alensi.local", "Alensi", "Admin", true);
    private static final KeycloakUser ALICE = new KeycloakUser(UUID.randomUUID(), "alice", "alice@alensi.local", "Alice", "Wanjiru", true);
    private static final KeycloakUser BOB = new KeycloakUser(UUID.randomUUID(), "bob", "bob@alensi.local", "Bob", "Otieno", true);

    @Autowired
    MockMvc mvc;

    @MockitoBean
    KeycloakAdminClient keycloak;

    @BeforeEach
    void keycloakUsers() {
        for (KeycloakUser user : new KeycloakUser[] { ADMIN, ALICE, BOB }) {
            given(keycloak.findById(user.id())).willReturn(Optional.of(user));
            given(keycloak.findByUsername(user.username())).willReturn(Optional.of(user));
        }
        given(keycloak.findOrganizationId(org.mockito.ArgumentMatchers.anyString())).willReturn(Optional.of("org-id"));
    }

    @Test
    void adminDefinesAclAndServicesQueryIt() throws Exception {
        // Bootstrap admin is provisioned on first call and holds alensi-identity/admin on *.
        call(ADMIN, get("/api/users/me")).andExpect(status().isOk()).andExpect(jsonPath("$.username").value("admin"));
        call(ADMIN, get("/api/users/admin/grants")).andExpect(jsonPath("$[0].role").value("platform-admin"))
                .andExpect(jsonPath("$[0].target").value("*"));

        // Catalog: an app with permissions and a role, and a country > city target hierarchy.
        send(ADMIN, post("/api/applications"), """
                {"code": "alensi-pay", "name": "Alensi Pay"}""").andExpect(status().isCreated());
        send(ADMIN, post("/api/applications/alensi-pay/permissions"), """
                {"code": "payments.view"}""").andExpect(status().isCreated());
        send(ADMIN, post("/api/applications/alensi-pay/permissions"), """
                {"code": "payments.refund"}""").andExpect(status().isCreated());
        send(ADMIN, post("/api/applications/alensi-pay/roles"), """
                {"code": "support", "name": "Support", "permissions": ["payments.view"]}""")
                .andExpect(status().isCreated());
        send(ADMIN, post("/api/applications/alensi-pay/roles"), """
                {"code": "finance", "name": "Finance", "permissions": ["payments.view", "payments.refund"]}""")
                .andExpect(status().isCreated());
        send(ADMIN, post("/api/target-types"), """
                {"code": "country", "name": "Country"}""").andExpect(status().isCreated());
        send(ADMIN, post("/api/target-types"), """
                {"code": "city", "name": "City", "parent": "country"}""").andExpect(status().isCreated());
        send(ADMIN, post("/api/tenants"), """
                {"code": "KE", "name": "Kenya", "rootType": "country"}""").andExpect(status().isCreated());
        send(ADMIN, post("/api/targets"), """
                {"code": "NBO", "name": "Nairobi", "type": "city", "parent": "KE"}""").andExpect(status().isCreated());
        send(ADMIN, post("/api/tenants"), """
                {"code": "UG", "name": "Uganda", "rootType": "country"}""").andExpect(status().isCreated());
        send(ADMIN, post("/api/targets"), """
                {"code": "KLA", "name": "Kampala", "type": "city"}""").andExpect(status().isBadRequest());

        // Alice: support everywhere in Kenya, finance only in Nairobi.
        send(ADMIN, post("/api/users/alice/grants"), """
                {"application": "alensi-pay", "role": "support", "target": "KE"}""").andExpect(status().isCreated());
        send(ADMIN, post("/api/users/alice/grants"), """
                {"application": "alensi-pay", "role": "finance", "target": "NBO"}""").andExpect(status().isCreated());
        send(ADMIN, post("/api/users/alice/grants"), """
                {"application": "alensi-pay", "role": "finance", "target": "NBO"}""").andExpect(status().isConflict());

        // Alice reads her own permissions.
        call(ALICE, get("/api/users/me/applications/alensi-pay/permissions?compressed=true"))
                .andExpect(jsonPath("$.country.KE[0]").value("payments.view"))
                .andExpect(jsonPath("$.city.NBO.length()").value(2));
        call(ALICE, get("/api/users/me/applications/alensi-pay/permissions/payments.refund/targets/NBO"))
                .andExpect(jsonPath("$.allowed").value(true));
        call(ALICE, get("/api/users/me/applications/alensi-pay/permissions/payments.refund/targets/KE"))
                .andExpect(jsonPath("$.allowed").value(false));
        call(ALICE, get("/api/users/me/applications/alensi-pay/permissions/payments.view/targets/UG"))
                .andExpect(jsonPath("$.allowed").value(false));
        call(ALICE, get("/api/users/me/applications/alensi-pay/permissions/payments.view/targets"))
                .andExpect(jsonPath("$").value(org.hamcrest.Matchers.contains("KE", "NBO")));

        // Alice may not read others' permissions or change the ACL.
        call(ALICE, get("/api/users/admin/applications/alensi-pay/permissions")).andExpect(status().isForbidden());
        send(ALICE, post("/api/applications"), """
                {"code": "x", "name": "X"}""").andExpect(status().isForbidden());

        // Bob is granted the identity "service" role and checks Alice on behalf of a service.
        send(ADMIN, post("/api/users/bob/grants"), """
                {"application": "alensi-identity", "role": "service"}""").andExpect(status().isCreated());
        call(BOB, get("/api/users/alice/applications/alensi-pay/permissions/payments.refund/targets/NBO"))
                .andExpect(jsonPath("$.allowed").value(true));

        // Suspending Alice blocks her and removes her effective permissions.
        send(ADMIN, put("/api/users/username/alice/access"), """
                {"status": "SUSPENDED"}""").andExpect(status().isOk());
        call(ALICE, get("/api/users/me")).andExpect(status().isForbidden());
        call(BOB, get("/api/users/alice/applications/alensi-pay/permissions/payments.refund/targets/NBO"))
                .andExpect(jsonPath("$.allowed").value(false));

        // Revoking a grant is audited.
        send(ADMIN, put("/api/users/username/alice/access"), """
                {"status": "ACTIVE"}""").andExpect(status().isOk());
        call(ADMIN, delete("/api/users/alice/grants/999999")).andExpect(status().isNotFound());
        call(ADMIN, get("/api/audit-events?size=1")).andExpect(jsonPath("$[0].action").value("user.access-updated"));
    }

    @Test
    void unauthenticatedRequestsAreRejected() throws Exception {
        mvc.perform(get("/api/users/me")).andExpect(status().isUnauthorized());
        mvc.perform(get("/actuator/health")).andExpect(status().isOk());
    }

    private ResultActions call(KeycloakUser user, MockHttpServletRequestBuilder request) throws Exception {
        return mvc.perform(request.with(token(user)));
    }

    private ResultActions send(KeycloakUser user, MockHttpServletRequestBuilder request, String body) throws Exception {
        return mvc.perform(request.with(token(user)).contentType(MediaType.APPLICATION_JSON).content(body));
    }

    /** Mirrors a lightweight Keycloak access token: subject and audience, no profile or role claims. */
    private static JwtRequestPostProcessor token(KeycloakUser user) {
        return jwt().jwt(token -> token.subject(user.id().toString()).audience(java.util.List.of("alensi-identity")));
    }
}
