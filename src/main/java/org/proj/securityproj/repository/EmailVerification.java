package org.proj.securityproj.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface EmailVerification extends JpaRepository<EmailVerification, Long> {
    Optional<EmailVerification> findByToken(String token);
}
