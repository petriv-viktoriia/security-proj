package org.proj.securityproj.repository;

import org.proj.securityproj.entity.LoginAttempt;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;

@Repository
public interface LoginAttemptRepository extends JpaRepository<LoginAttempt,Long> {
    List<LoginAttempt> findByEmailOrderByAttemptTimeDesc(String email);

    Page<LoginAttempt> findAllByOrderByAttemptTimeDesc(Pageable pageable);

    List<LoginAttempt> findByEmailAndAttemptTimeAfter(String email, Instant after);

}
