package io.alensi.keycloak.sms;

import org.jboss.logging.Logger;

/** Writes messages to the log instead of sending them. Never use outside development: codes end up in logs. */
class LogSmsSender implements SmsSender {

    private static final Logger LOG = Logger.getLogger(LogSmsSender.class);

    @Override
    public void send(String to, String message) {
        LOG.warnf("[DEV SMS] to %s: %s", to, message);
    }

    @Override
    public String name() {
        return "log (development only)";
    }
}
