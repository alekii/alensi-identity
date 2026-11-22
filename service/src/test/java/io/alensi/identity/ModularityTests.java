package io.alensi.identity;

import org.junit.jupiter.api.Test;
import org.springframework.modulith.core.ApplicationModules;
import org.springframework.modulith.docs.Documenter;

/**
 * Each direct sub-package of {@code io.alensi.identity} is an application module. Fails on
 * dependency cycles between modules and on use of another module's internals.
 */
class ModularityTests {

    private static final ApplicationModules MODULES = ApplicationModules.of(IdentityApplication.class);

    @Test
    void modulesHaveNoCyclesAndRespectBoundaries() {
        MODULES.verify();
    }

    /** Module diagrams (PlantUML) and canvases under target/spring-modulith-docs. */
    @Test
    void documentModules() {
        new Documenter(MODULES).writeDocumentation();
    }
}
