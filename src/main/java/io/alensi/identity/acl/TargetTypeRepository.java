package io.alensi.identity.acl;

import java.util.List;
import java.util.Optional;

import io.alensi.identity.tenant.Tenant;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface TargetTypeRepository extends JpaRepository<TargetType, Long> {

    Optional<TargetType> findByCodeAndTenantIsNull(String code);

    Optional<TargetType> findByCodeAndTenant(String code, Tenant tenant);

    boolean existsByCodeAndTenantIsNull(String code);

    /** True if any type, shared or tenant-defined, uses the code. */
    boolean existsByCode(String code);

    @Query("select t from TargetType t left join fetch t.parent left join fetch t.tenant order by t.code")
    List<TargetType> findAllWithParentAndTenant();
}
