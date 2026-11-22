package io.alensi.identity.acl;

import java.util.Collection;
import java.util.List;
import java.util.Set;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface PermissionRepository extends JpaRepository<Permission, Long> {

    List<Permission> findByApplicationOrderByCode(Application application);

    List<Permission> findByApplicationAndCodeIn(Application application, Collection<String> codes);

    boolean existsByApplicationAndCode(Application application, String code);

    @Query("select p.code from Permission p where p.application.code = :applicationCode and p.limited = true")
    Set<String> findLimitedCodes(String applicationCode);
}
