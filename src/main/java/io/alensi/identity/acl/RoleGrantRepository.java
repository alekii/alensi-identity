package io.alensi.identity.acl;

import java.util.List;

import io.alensi.identity.user.UserAccount;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface RoleGrantRepository extends JpaRepository<RoleGrant, Long> {

    @Query("""
            select distinct g from RoleGrant g
              join fetch g.role r
              join fetch r.application a
              left join fetch r.permissions
              left join fetch r.assignableRoles
              left join fetch g.target
            where g.user = :user and a.code = :applicationCode
            """)
    List<RoleGrant> findForUserInApplication(UserAccount user, String applicationCode);

    @Query("""
            select g from RoleGrant g
              join fetch g.role r
              join fetch r.application
              left join fetch g.target
            where g.user = :user
            order by g.id
            """)
    List<RoleGrant> findForUser(UserAccount user);

    boolean existsByUserAndRoleAndTarget(UserAccount user, Role role, Target target);

    boolean existsByUserAndRoleAndTargetIsNull(UserAccount user, Role role);
}
