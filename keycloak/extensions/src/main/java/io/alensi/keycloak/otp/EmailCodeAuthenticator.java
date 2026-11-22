package io.alensi.keycloak.otp;

import java.time.Duration;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.email.EmailSenderProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/** Sends the one-time code to the user's email address, through the realm's SMTP settings. */
public class EmailCodeAuthenticator extends AbstractCodeAuthenticator {

    @Override
    protected String notePrefix() {
        return "alensi.email.";
    }

    @Override
    protected String sentMessageKey() {
        return "alensiCodeEmailSent";
    }

    @Override
    protected String maskedDestination(UserModel user) {
        return Masking.email(user.getEmail());
    }

    @Override
    protected void send(AuthenticationFlowContext context, String code, Duration ttl) throws Exception {
        RealmModel realm = context.getRealm();
        String realmName = realmName(realm);
        long minutes = Math.max(1, ttl.toMinutes());
        String text = "Your %s verification code is %s. It expires in %d minutes. If you did not try to sign in, "
                .formatted(realmName, code, minutes) + "change your password.";
        String html = "<p>Your %s verification code is</p><p style=\"font-size:24px;font-weight:bold;letter-spacing:4px\">%s</p>"
                .formatted(escape(realmName), code)
                + "<p>It expires in %d minutes. If you did not try to sign in, change your password.</p>".formatted(minutes);
        context.getSession().getProvider(EmailSenderProvider.class)
                .send(realm.getSmtpConfig(), context.getUser(), "%s verification code".formatted(realmName), text, html);
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return user.getEmail() != null && !user.getEmail().isBlank();
    }

    private static String escape(String value) {
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }
}
