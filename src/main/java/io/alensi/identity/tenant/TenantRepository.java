package io.alensi.identity.tenant;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

public interface TenantRepository extends JpaRepository<Tenant, Long> {

    Optional<Tenant> findByCode(String code);

    Optional<Tenant> findByKeycloakRealmAndKeycloakOrganization(String realm, String organization);

    boolean existsByCode(String code);
}
