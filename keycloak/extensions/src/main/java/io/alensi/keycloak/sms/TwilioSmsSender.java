package io.alensi.keycloak.sms;

import java.net.URI;
import java.net.http.HttpRequest;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

/** Twilio Programmable Messaging API. */
class TwilioSmsSender implements SmsSender {

    private final URI endpoint;
    private final String authorization;
    private final String from;

    TwilioSmsSender(String accountSid, String authToken, String from) {
        this.endpoint = URI.create("https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json".formatted(accountSid));
        this.authorization = "Basic " + Base64.getEncoder()
                .encodeToString((accountSid + ":" + authToken).getBytes(StandardCharsets.UTF_8));
        this.from = from;
    }

    @Override
    public void send(String to, String message) throws Exception {
        HttpSms.post(HttpRequest.newBuilder(endpoint).header("Authorization", authorization),
                HttpSms.form(Map.of("To", to, "From", from, "Body", message)), name());
    }

    @Override
    public String name() {
        return "Twilio";
    }
}
