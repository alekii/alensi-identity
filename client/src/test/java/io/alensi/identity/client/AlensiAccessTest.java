package io.alensi.identity.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.ExpectedCount.once;
import static org.springframework.test.web.client.ExpectedCount.times;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.headerDoesNotExist;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withServiceUnavailable;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import java.math.BigDecimal;
import java.net.URI;
import java.time.Duration;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

class AlensiAccessTest {

    private static final String PERMISSIONS = "http://identity/api/users/me/applications/alensi-insure/permissions";

    private MockRestServiceServer identity;
    private AlensiAccess access;
    private MockHttpServletRequest request;

    @BeforeEach
    void setUp() {
        RestClient.Builder builder = RestClient.builder();
        identity = MockRestServiceServer.bindTo(builder).build();
        var properties = new AlensiIdentityProperties(URI.create("http://identity"), "alensi-insure", Duration.ofSeconds(30), 100L);
        access = new AlensiAccess(new AlensiIdentityClient(builder, properties), properties);
        request = new MockHttpServletRequest();
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        signIn("brian", List.of());
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    void fetchesThePermissionMapOnceAndAnswersFromIt() {
        identity.expect(once(), requestTo(PERMISSIONS))
                .andExpect(header("Authorization", "Bearer token-brian"))
                .andExpect(headerDoesNotExist(AlensiIdentityClient.TENANT_HEADER))
                .andRespond(json("""
                        {"branch": {"JUB-NBO": ["claims.view"]}, "team": {"JUB-NBO-T1": ["claims.view"]}}"""));

        assertThat(access.can("claims.view", "JUB-NBO-T1")).isTrue();
        assertThat(access.can("claims.view", "JUB-MSA")).isFalse();
        assertThat(access.scope("claims.view").targets()).containsExactlyInAnyOrder("JUB-NBO", "JUB-NBO-T1");
        assertThatThrownBy(() -> access.require("claims.view", "JUB-MSA")).isInstanceOf(AccessDeniedException.class);
        identity.verify();
    }

    @Test
    void eachTenantIsAskedAndCachedSeparately() {
        identity.expect(once(), requestTo(PERMISSIONS)).andExpect(header(AlensiIdentityClient.TENANT_HEADER, "JUB"))
                .andRespond(json("""
                        {"branch": {"JUB-NBO": ["policies.sell"]}}"""));
        identity.expect(once(), requestTo(PERMISSIONS)).andExpect(header(AlensiIdentityClient.TENANT_HEADER, "MAD"))
                .andRespond(json("""
                        {"branch": {"MAD-MSA": ["policies.sell"]}}"""));

        request.addHeader(AlensiIdentityClient.TENANT_HEADER, "JUB");
        assertThat(access.scope("policies.sell").targets()).containsExactly("JUB-NBO");
        request.removeHeader(AlensiIdentityClient.TENANT_HEADER);
        request.addHeader(AlensiIdentityClient.TENANT_HEADER, "MAD");
        assertThat(access.scope("policies.sell").targets()).containsExactly("MAD-MSA");
        identity.verify();
    }

    @Test
    void tokensForDifferentOrganizationsDoNotShareACacheEntry() {
        identity.expect(times(2), requestTo(PERMISSIONS)).andRespond(json("{}"));
        signIn("brian", List.of("jub"));
        access.can("policies.sell");
        signIn("brian", List.of("mad"));
        access.can("policies.sell");
        identity.verify();
    }

    @Test
    void wildcardGrantsCoverEverything() {
        identity.expect(requestTo(PERMISSIONS)).andRespond(json("""
                {"*": {"*": ["claims.view"]}}"""));
        assertThat(access.scope("claims.view").all()).isTrue();
        assertThat(access.can("claims.view", "ANY-BRANCH")).isTrue();
    }

    @Test
    void limitDecisionsAreLiveAndCarryTheLimit() {
        String approve = "http://identity/api/users/me/applications/alensi-insure/permissions/claims.approve/targets/JUB-NBO?amount=3000000&currency=KES";
        identity.expect(times(2), requestTo(approve)).andRespond(json("""
                {"allowed": false, "limits": [{"permission": "claims.approve", "currency": "KES", "maxAmount": 1000000}]}"""));

        Decision decision = access.decide("claims.approve", "JUB-NBO", new BigDecimal("3000000"), "KES");
        access.decide("claims.approve", "JUB-NBO", new BigDecimal("3000000"), "KES");

        assertThat(decision.allowed()).isFalse();
        assertThat(decision.limits().getFirst().maxAmount()).isEqualByComparingTo("1000000");
        identity.verify();
    }

    @Test
    void failsClosedWhenIdentityCannotAnswer() {
        identity.expect(requestTo(PERMISSIONS)).andRespond(withServiceUnavailable());
        assertThatThrownBy(() -> access.can("claims.view", "JUB-NBO"))
                .isInstanceOf(AlensiIdentityException.class)
                .extracting(e -> ((AlensiIdentityException) e).status()).isEqualTo(503);
    }

    @Test
    void identityRefusalsBecomeAccessDenied() {
        identity.expect(requestTo(PERMISSIONS)).andRespond(withStatus(HttpStatus.FORBIDDEN));
        request.addHeader(AlensiIdentityClient.TENANT_HEADER, "MAD");
        assertThatThrownBy(() -> access.can("claims.view", "MAD-MSA")).isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void requiresAnAuthenticatedRequest() {
        SecurityContextHolder.clearContext();
        assertThatThrownBy(() -> access.can("claims.view")).isInstanceOf(AuthenticationCredentialsNotFoundException.class);
    }

    private void signIn(String subject, List<String> organizations) {
        Jwt.Builder jwt = Jwt.withTokenValue("token-" + subject).header("alg", "none").subject(subject);
        if (!organizations.isEmpty()) {
            jwt.claim("organization", organizations);
        }
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt.build()));
    }

    private static org.springframework.test.web.client.ResponseCreator json(String body) {
        return withSuccess(body, MediaType.APPLICATION_JSON);
    }
}
