package io.alensi.identity.client;

/**
 * alensi-identity could not answer (unreachable, or an unexpected response). Checks fail closed:
 * this propagates instead of being treated as "allowed" or "denied".
 */
public class AlensiIdentityException extends RuntimeException {

    private final int status;

    public AlensiIdentityException(int status, String message, Throwable cause) {
        super(message, cause);
        this.status = status;
    }

    /** HTTP status from identity, or 0 if it could not be reached. */
    public int status() {
        return status;
    }
}
