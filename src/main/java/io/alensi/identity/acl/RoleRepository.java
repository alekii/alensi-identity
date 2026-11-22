package io.alensi.identity.acl;

import java.util.List;
import java.util.Optional;

import io.alensi.identity.tenant.Tenant;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<Role, Long> {

    @EntityGraph(attributePaths = { "permissions", "tenant", "limits", "assignableRoles", "assignableRoles.application",
            "assignableRoles.tenant" })
    List<Role> findByApplicationOrderByCode(Application application);

    Optional<Role> findByApplicationAndCodeAndTenantIsNull(Application application, String code);

    Optional<Role> findByApplicationAndCodeAndTenant(Application application, String code, Tenant tenant);

    /** True if any role, shared or tenant-owned, uses the code. */
    boolean existsByApplicationAndCode(Application application, String code);

    boolean existsByApplicationAndCodeAndTenantIsNull(Application application, String code);

    boolean existsByApplicationAndCodeAndTenant(Application application, String code, Tenant tenant);
}
