package io.alensi.identity.acl;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

public interface TargetTypeRepository extends JpaRepository<TargetType, Long> {

    Optional<TargetType> findByCode(String code);

    boolean existsByCode(String code);
}
