package io.alensi.identity.acl;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<Role, Long> {

    @EntityGraph(attributePaths = { "permissions", "owner", "limits", "assignableRoles", "assignableRoles.application",
            "assignableRoles.owner" })
    List<Role> findByApplicationOrderByCode(Application application);

    Optional<Role> findByApplicationAndCodeAndOwnerIsNull(Application application, String code);

    Optional<Role> findByApplicationAndCodeAndOwner(Application application, String code, Target owner);

    /** True if any role, platform-wide or company-owned, uses the code. */
    boolean existsByApplicationAndCode(Application application, String code);

    boolean existsByApplicationAndCodeAndOwnerIsNull(Application application, String code);

    boolean existsByApplicationAndCodeAndOwner(Application application, String code, Target owner);
}
