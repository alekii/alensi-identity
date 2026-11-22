package io.alensi.keycloak.otp;

import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;

public class EmailCodeAuthenticatorFactory extends AbstractCodeAuthenticatorFactory {

    public static final String ID = "alensi-email-code";

    private static final EmailCodeAuthenticator INSTANCE = new EmailCodeAuthenticator();

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public String getDisplayType() {
        return "Email code";
    }

    @Override
    public String getHelpText() {
        return "Sign in with a one-time code sent to your email address.";
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return INSTANCE;
    }
}
