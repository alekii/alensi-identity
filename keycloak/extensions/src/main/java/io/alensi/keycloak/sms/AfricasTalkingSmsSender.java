package io.alensi.keycloak.sms;

import java.net.URI;
import java.net.http.HttpRequest;
import java.util.LinkedHashMap;
import java.util.Map;

/** Africa's Talking bulk SMS API. */
class AfricasTalkingSmsSender implements SmsSender {

    private final String username;
    private final String apiKey;
    private final String senderId;
    private final URI endpoint;

    AfricasTalkingSmsSender(String username, String apiKey, String senderId, boolean sandbox) {
        this.username = username;
        this.apiKey = apiKey;
        this.senderId = senderId;
        this.endpoint = URI.create(sandbox
                ? "https://api.sandbox.africastalking.com/version1/messaging"
                : "https://api.africastalking.com/version1/messaging");
    }

    @Override
    public void send(String to, String message) throws Exception {
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("username", username);
        fields.put("to", to);
        fields.put("message", message);
        if (senderId != null && !senderId.isBlank()) {
            fields.put("from", senderId);
        }
        HttpSms.post(HttpRequest.newBuilder(endpoint).header("apiKey", apiKey), HttpSms.form(fields), name());
    }

    @Override
    public String name() {
        return "Africa's Talking";
    }
}
