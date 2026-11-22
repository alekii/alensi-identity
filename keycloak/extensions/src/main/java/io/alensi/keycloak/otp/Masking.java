package io.alensi.keycloak.otp;

/** Partly hides where a code was sent, e.g. {@code a***@alensi.co.ke}, {@code +2547•••••678}. */
final class Masking {

    private Masking() {
    }

    static String email(String email) {
        if (email == null) {
            return "";
        }
        int at = email.indexOf('@');
        if (at <= 1) {
            return email;
        }
        return email.charAt(0) + "***" + email.substring(at);
    }

    static String phone(String phone) {
        if (phone == null || phone.length() < 8) {
            return phone == null ? "" : phone;
        }
        return phone.substring(0, 5) + "•".repeat(phone.length() - 8) + phone.substring(phone.length() - 3);
    }
}
