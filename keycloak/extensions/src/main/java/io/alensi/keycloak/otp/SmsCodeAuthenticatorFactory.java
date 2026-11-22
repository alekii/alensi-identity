package io.alensi.keycloak.otp;

import io.alensi.keycloak.sms.SmsSender;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;

/**
 * The SMS provider comes from the environment: {@code ALENSI_SMS_PROVIDER} = {@code log} (default,
 * development only), {@code africastalking} or {@code twilio}; see {@link SmsSender#fromEnvironment}.
 */
public class SmsCodeAuthenticatorFactory extends AbstractCodeAuthenticatorFactory {

    public static final String ID = "alensi-sms-code";

    private static final Logger LOG = Logger.getLogger(SmsCodeAuthenticatorFactory.class);

    private SmsCodeAuthenticator instance;

    @Override
    public void init(Config.Scope config) {
        SmsSender sender = SmsSender.fromEnvironment(System.getenv());
        LOG.infof("SMS codes are sent with %s", sender.name());
        instance = new SmsCodeAuthenticator(sender);
    }

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public String getDisplayType() {
        return "SMS code";
    }

    @Override
    public String getHelpText() {
        return "Sign in with a one-time code sent to your phone by SMS.";
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return instance;
    }
}
