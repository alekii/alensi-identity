package io.alensi.identity.acl;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

public interface ApplicationRepository extends JpaRepository<Application, Long> {

    Optional<Application> findByCode(String code);

    boolean existsByCode(String code);
}
