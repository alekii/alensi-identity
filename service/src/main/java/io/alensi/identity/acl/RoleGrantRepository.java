package io.alensi.identity.acl;

import java.util.List;

import io.alensi.identity.user.UserAccount;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface RoleGrantRepository extends JpaRepository<RoleGrant, Long> {

    /**
     * Role collections (permissions, assignable roles, limits) are batch-loaded afterwards; fetch-joining
     * all three here multiplies rows into a cartesian product.
     */
    @Query("""
            select g from RoleGrant g
              join fetch g.role r
              join fetch r.application a
              left join fetch g.target
            where g.user = :user and a.code = :applicationCode
            """)
    List<RoleGrant> findForUserInApplication(UserAccount user, String applicationCode);

    @Query("""
            select g from RoleGrant g
              join fetch g.role r
              join fetch r.application
              left join fetch r.tenant
              left join fetch g.target
              left join fetch g.tenant
            where g.user = :user
            order by g.id
            """)
    List<RoleGrant> findForUser(UserAccount user);

    boolean existsByUserAndRoleAndTarget(UserAccount user, Role role, Target target);

    boolean existsByUserAndRoleAndTargetIsNull(UserAccount user, Role role);
}
