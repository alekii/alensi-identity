package io.alensi.keycloak.otp;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;

/**
 * A one-time code issued during a login, kept in the authentication session's notes. Pure logic so
 * it can be tested without Keycloak.
 */
public record CodeChallenge(String code, Instant expiresAt, Instant sentAt, int failedAttempts) {

    private static final SecureRandom RANDOM = new SecureRandom();

    public enum Result {
        VALID, INVALID, EXPIRED, TOO_MANY_ATTEMPTS
    }

    public static CodeChallenge issue(int length, Duration ttl, Instant now) {
        StringBuilder code = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            code.append(RANDOM.nextInt(10));
        }
        return new CodeChallenge(code.toString(), now.plus(ttl), now, 0);
    }

    /** Checks a submitted code. Attempts are counted before comparing, so the last allowed attempt still counts. */
    public Result verify(String submitted, Instant now, int maxAttempts) {
        if (failedAttempts >= maxAttempts) {
            return Result.TOO_MANY_ATTEMPTS;
        }
        if (!now.isBefore(expiresAt)) {
            return Result.EXPIRED;
        }
        boolean matches = submitted != null && MessageDigest.isEqual(
                code.getBytes(StandardCharsets.UTF_8), submitted.trim().getBytes(StandardCharsets.UTF_8));
        return matches ? Result.VALID : Result.INVALID;
    }

    public CodeChallenge withFailedAttempt() {
        return new CodeChallenge(code, expiresAt, sentAt, failedAttempts + 1);
    }

    /** A new code may only be sent once the cooldown since the last one has passed. */
    public boolean canResend(Instant now, Duration cooldown) {
        return !now.isBefore(sentAt.plus(cooldown));
    }

    // ---- persistence in authentication session notes ----

    public Map<String, String> toNotes(String prefix) {
        return Map.of(prefix + "code", code, prefix + "expires", expiresAt.toString(), prefix + "sent",
                sentAt.toString(), prefix + "failed", Integer.toString(failedAttempts));
    }

    public static CodeChallenge fromNotes(String prefix, Map<String, String> notes) {
        String code = notes.get(prefix + "code");
        if (code == null) {
            return null;
        }
        return new CodeChallenge(code, Instant.parse(notes.get(prefix + "expires")),
                Instant.parse(notes.get(prefix + "sent")), Integer.parseInt(notes.get(prefix + "failed")));
    }

    public static String[] noteKeys(String prefix) {
        return new String[] { prefix + "code", prefix + "expires", prefix + "sent", prefix + "failed" };
    }
}
