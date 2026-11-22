package io.alensi.keycloak.otp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.time.Instant;

import org.junit.jupiter.api.Test;

class CodeChallengeTest {

    private static final Instant NOW = Instant.parse("2026-11-22T10:00:00Z");

    @Test
    void issuesNumericCodesOfTheRequestedLength() {
        CodeChallenge challenge = CodeChallenge.issue(6, Duration.ofMinutes(5), NOW);
        assertTrue(challenge.code().matches("\\d{6}"));
        assertEquals(NOW.plusSeconds(300), challenge.expiresAt());
    }

    @Test
    void acceptsTheCodeUntilItExpires() {
        CodeChallenge challenge = new CodeChallenge("123456", NOW.plusSeconds(300), NOW, 0);
        assertEquals(CodeChallenge.Result.VALID, challenge.verify(" 123456 ", NOW.plusSeconds(299), 5));
        assertEquals(CodeChallenge.Result.INVALID, challenge.verify("654321", NOW, 5));
        assertEquals(CodeChallenge.Result.INVALID, challenge.verify(null, NOW, 5));
        assertEquals(CodeChallenge.Result.EXPIRED, challenge.verify("123456", NOW.plusSeconds(300), 5));
    }

    @Test
    void locksAfterTooManyFailures() {
        CodeChallenge challenge = new CodeChallenge("123456", NOW.plusSeconds(300), NOW, 0);
        for (int i = 0; i < 5; i++) {
            challenge = challenge.withFailedAttempt();
        }
        assertEquals(CodeChallenge.Result.TOO_MANY_ATTEMPTS, challenge.verify("123456", NOW, 5));
    }

    @Test
    void resendRespectsTheCooldown() {
        CodeChallenge challenge = new CodeChallenge("123456", NOW.plusSeconds(300), NOW, 0);
        assertFalse(challenge.canResend(NOW.plusSeconds(29), Duration.ofSeconds(30)));
        assertTrue(challenge.canResend(NOW.plusSeconds(30), Duration.ofSeconds(30)));
    }

    @Test
    void roundTripsThroughSessionNotes() {
        CodeChallenge challenge = new CodeChallenge("123456", NOW.plusSeconds(300), NOW, 2);
        assertEquals(challenge, CodeChallenge.fromNotes("p.", challenge.toNotes("p.")));
    }

    @Test
    void masksDestinations() {
        assertEquals("a***@alensi.co.ke", Masking.email("alice@alensi.co.ke"));
        assertEquals("+2547•••••678", Masking.phone("+254712345678"));
    }
}
