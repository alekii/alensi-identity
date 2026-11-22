package io.alensi.keycloak.sms;

import java.util.Map;

/** Delivers a text message to an E.164 phone number. */
public interface SmsSender {

    void send(String to, String message) throws Exception;

    String name();

    /**
     * Chooses the provider from {@code ALENSI_SMS_PROVIDER}:
     * <ul>
     * <li>{@code log} (default): writes the message to the Keycloak log. Development only.</li>
     * <li>{@code africastalking}: {@code ALENSI_SMS_AT_USERNAME}, {@code ALENSI_SMS_AT_API_KEY}, optional
     * {@code ALENSI_SMS_AT_SENDER_ID}; {@code ALENSI_SMS_AT_SANDBOX=true} for the sandbox.</li>
     * <li>{@code twilio}: {@code ALENSI_SMS_TWILIO_ACCOUNT_SID}, {@code ALENSI_SMS_TWILIO_AUTH_TOKEN},
     * {@code ALENSI_SMS_TWILIO_FROM}.</li>
     * </ul>
     */
    static SmsSender fromEnvironment(Map<String, String> env) {
        String provider = env.getOrDefault("ALENSI_SMS_PROVIDER", "log");
        return switch (provider) {
            case "log" -> new LogSmsSender();
            case "africastalking" -> new AfricasTalkingSmsSender(require(env, "ALENSI_SMS_AT_USERNAME"),
                    require(env, "ALENSI_SMS_AT_API_KEY"), env.get("ALENSI_SMS_AT_SENDER_ID"),
                    Boolean.parseBoolean(env.get("ALENSI_SMS_AT_SANDBOX")));
            case "twilio" -> new TwilioSmsSender(require(env, "ALENSI_SMS_TWILIO_ACCOUNT_SID"),
                    require(env, "ALENSI_SMS_TWILIO_AUTH_TOKEN"), require(env, "ALENSI_SMS_TWILIO_FROM"));
            default -> throw new IllegalArgumentException("Unknown ALENSI_SMS_PROVIDER '%s'".formatted(provider));
        };
    }

    private static String require(Map<String, String> env, String key) {
        String value = env.get(key);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(key + " is required for the configured SMS provider");
        }
        return value;
    }
}
