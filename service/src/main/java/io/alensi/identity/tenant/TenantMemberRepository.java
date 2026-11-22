package io.alensi.identity.tenant;

import java.util.List;
import java.util.Optional;

import io.alensi.identity.user.UserAccount;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface TenantMemberRepository extends JpaRepository<TenantMember, TenantMember.Key> {

    Optional<TenantMember> findByTenantAndUser(Tenant tenant, UserAccount user);

    @Query("select m from TenantMember m join fetch m.tenant where m.user = :user")
    List<TenantMember> findByUser(UserAccount user);

    @Query("select m from TenantMember m join fetch m.user where m.tenant = :tenant order by m.user.username")
    List<TenantMember> findByTenant(Tenant tenant);
}
