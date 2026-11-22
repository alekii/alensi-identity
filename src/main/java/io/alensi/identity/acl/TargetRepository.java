package io.alensi.identity.acl;

import java.util.List;
import java.util.Optional;

import io.alensi.identity.tenant.Tenant;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface TargetRepository extends JpaRepository<Target, Long> {

    Optional<Target> findByCode(String code);

    boolean existsByCode(String code);

    Optional<Target> findByTenantAndParentIsNull(Tenant tenant);

    @Query("select t from Target t join fetch t.type join fetch t.tenant left join fetch t.parent")
    List<Target> findAllWithTypeAndParent();
}
