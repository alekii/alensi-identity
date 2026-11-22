package io.alensi.identity.acl;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<Role, Long> {

    @EntityGraph(attributePaths = { "permissions", "assignableRoles", "assignableRoles.application" })
    List<Role> findByApplicationOrderByCode(Application application);

    Optional<Role> findByApplicationAndCode(Application application, String code);

    boolean existsByApplicationAndCode(Application application, String code);
}
