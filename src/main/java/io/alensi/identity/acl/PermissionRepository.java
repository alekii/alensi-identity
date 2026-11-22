package io.alensi.identity.acl;

import java.util.Collection;
import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

public interface PermissionRepository extends JpaRepository<Permission, Long> {

    List<Permission> findByApplicationOrderByCode(Application application);

    List<Permission> findByApplicationAndCodeIn(Application application, Collection<String> codes);

    boolean existsByApplicationAndCode(Application application, String code);
}
