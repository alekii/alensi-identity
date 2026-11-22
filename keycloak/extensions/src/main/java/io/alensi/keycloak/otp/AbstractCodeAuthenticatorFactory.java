package io.alensi.keycloak.otp;

import java.util.List;

import org.keycloak.Config;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

abstract class AbstractCodeAuthenticatorFactory implements AuthenticatorFactory {

    private static final Requirement[] REQUIREMENTS = { Requirement.REQUIRED, Requirement.ALTERNATIVE, Requirement.DISABLED };

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public Requirement[] getRequirementChoices() {
        return REQUIREMENTS;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return ProviderConfigurationBuilder.create()
                .property().name(AbstractCodeAuthenticator.CONFIG_LENGTH).label("Code length")
                .type(ProviderConfigProperty.INTEGER_TYPE).defaultValue(6).add()
                .property().name(AbstractCodeAuthenticator.CONFIG_TTL_SECONDS).label("Code lifetime (seconds)")
                .type(ProviderConfigProperty.INTEGER_TYPE).defaultValue(300).add()
                .property().name(AbstractCodeAuthenticator.CONFIG_MAX_ATTEMPTS).label("Attempts per code")
                .type(ProviderConfigProperty.INTEGER_TYPE).defaultValue(5).add()
                .property().name(AbstractCodeAuthenticator.CONFIG_RESEND_COOLDOWN_SECONDS).label("Re-send cooldown (seconds)")
                .type(ProviderConfigProperty.INTEGER_TYPE).defaultValue(30).add()
                .build();
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }
}
