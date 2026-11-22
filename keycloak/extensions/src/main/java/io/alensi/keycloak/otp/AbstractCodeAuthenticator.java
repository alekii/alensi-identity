package io.alensi.keycloak.otp;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * Second factor: sends a one-time code over a channel (email, SMS) and checks it. The code lives in
 * the authentication session, expires, allows a few attempts, and can be re-sent after a cooldown.
 */
public abstract class AbstractCodeAuthenticator implements Authenticator {

    static final String FIELD = "code";
    static final String TEMPLATE = "alensi-code.ftl";

    static final String CONFIG_LENGTH = "length";
    static final String CONFIG_TTL_SECONDS = "ttlSeconds";
    static final String CONFIG_MAX_ATTEMPTS = "maxAttempts";
    static final String CONFIG_RESEND_COOLDOWN_SECONDS = "resendCooldownSeconds";

    private static final Logger LOG = Logger.getLogger(AbstractCodeAuthenticator.class);

    /** Prefix for this channel's authentication-session notes, e.g. {@code alensi.email.}. */
    protected abstract String notePrefix();

    /** Message key for "we sent a code to {0}". */
    protected abstract String sentMessageKey();

    /** Where the code goes, partly hidden for display. */
    protected abstract String maskedDestination(UserModel user);

    protected abstract void send(AuthenticationFlowContext context, String code, Duration ttl) throws Exception;

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        CodeChallenge current = load(context);
        if (current == null || !Instant.now().isBefore(current.expiresAt())) {
            if (!issueAndSend(context)) {
                return;
            }
        }
        context.challenge(form(context, null, null));
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> params = context.getHttpRequest().getDecodedFormParameters();
        Instant now = Instant.now();
        CodeChallenge current = load(context);
        if (params.containsKey("resend")) {
            if (current != null && !current.canResend(now, Duration.ofSeconds(setting(context, CONFIG_RESEND_COOLDOWN_SECONDS, 30)))) {
                context.challenge(form(context, "alensiCodeResendWait", null));
            }
            else if (issueAndSend(context)) {
                context.challenge(form(context, null, "alensiCodeResent"));
            }
            return;
        }
        if (current == null) {
            if (issueAndSend(context)) {
                context.challenge(form(context, null, null));
            }
            return;
        }
        switch (current.verify(params.getFirst(FIELD), now, setting(context, CONFIG_MAX_ATTEMPTS, 5))) {
            case VALID -> {
                clear(context);
                context.success();
            }
            case EXPIRED -> {
                if (issueAndSend(context)) {
                    context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE, form(context, "alensiCodeExpired", null));
                }
            }
            case TOO_MANY_ATTEMPTS -> {
                // Kept (not cleared), so the only way on is an explicit re-send, which is rate limited.
                context.getEvent().user(context.getUser()).error(Errors.INVALID_USER_CREDENTIALS);
                context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
                        form(context, "alensiCodeTooManyAttempts", null));
            }
            case INVALID -> {
                save(context, current.withFailedAttempt());
                context.getEvent().user(context.getUser()).error(Errors.INVALID_USER_CREDENTIALS);
                context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, form(context, "alensiCodeInvalid", null));
            }
        }
    }

    private boolean issueAndSend(AuthenticationFlowContext context) {
        Duration ttl = Duration.ofSeconds(setting(context, CONFIG_TTL_SECONDS, 300));
        CodeChallenge challenge = CodeChallenge.issue(setting(context, CONFIG_LENGTH, 6), ttl, Instant.now());
        try {
            send(context, challenge.code(), ttl);
        }
        catch (Exception e) {
            LOG.errorf(e, "Could not send %s code to user %s", notePrefix(), context.getUser().getId());
            context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR, form(context, "alensiCodeSendFailed", null));
            return false;
        }
        save(context, challenge);
        return true;
    }

    private Response form(AuthenticationFlowContext context, String errorKey, String infoKey) {
        LoginFormsProvider form = context.form()
                .setAttribute("alensiCodeSentMessage", sentMessageKey())
                .setAttribute("alensiCodeDestination", maskedDestination(context.getUser()));
        if (errorKey != null) {
            form.addError(new FormMessage(FIELD, errorKey));
        }
        if (infoKey != null) {
            form.setInfo(infoKey);
        }
        return form.createForm(TEMPLATE);
    }

    private CodeChallenge load(AuthenticationFlowContext context) {
        AuthenticationSessionModel session = context.getAuthenticationSession();
        Map<String, String> notes = new HashMap<>();
        for (String key : CodeChallenge.noteKeys(notePrefix())) {
            String value = session.getAuthNote(key);
            if (value != null) {
                notes.put(key, value);
            }
        }
        return CodeChallenge.fromNotes(notePrefix(), notes);
    }

    private void save(AuthenticationFlowContext context, CodeChallenge challenge) {
        challenge.toNotes(notePrefix()).forEach(context.getAuthenticationSession()::setAuthNote);
    }

    private void clear(AuthenticationFlowContext context) {
        for (String key : CodeChallenge.noteKeys(notePrefix())) {
            context.getAuthenticationSession().removeAuthNote(key);
        }
    }

    static int setting(AuthenticationFlowContext context, String key, int fallback) {
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        if (config == null || config.getConfig() == null || config.getConfig().get(key) == null) {
            return fallback;
        }
        return Integer.parseInt(config.getConfig().get(key));
    }

    static String realmName(RealmModel realm) {
        return realm.getDisplayName() != null ? realm.getDisplayName() : realm.getName();
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }
}
