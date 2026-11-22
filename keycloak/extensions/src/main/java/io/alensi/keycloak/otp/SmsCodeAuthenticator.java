package io.alensi.keycloak.otp;

import java.time.Duration;

import io.alensi.keycloak.sms.SmsSender;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/** Sends the one-time code by SMS to the user's {@code phoneNumber} attribute (E.164, e.g. +254712345678). */
public class SmsCodeAuthenticator extends AbstractCodeAuthenticator {

    public static final String PHONE_ATTRIBUTE = "phoneNumber";

    private final SmsSender sender;

    SmsCodeAuthenticator(SmsSender sender) {
        this.sender = sender;
    }

    @Override
    protected String notePrefix() {
        return "alensi.sms.";
    }

    @Override
    protected String sentMessageKey() {
        return "alensiCodeSmsSent";
    }

    @Override
    protected String maskedDestination(UserModel user) {
        return Masking.phone(user.getFirstAttribute(PHONE_ATTRIBUTE));
    }

    @Override
    protected void send(AuthenticationFlowContext context, String code, Duration ttl) throws Exception {
        sender.send(context.getUser().getFirstAttribute(PHONE_ATTRIBUTE), "%s is your %s verification code. It expires in %d minutes."
                .formatted(code, realmName(context.getRealm()), Math.max(1, ttl.toMinutes())));
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        String phone = user.getFirstAttribute(PHONE_ATTRIBUTE);
        return phone != null && !phone.isBlank();
    }
}
