package org.proj.securityproj.service;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.proj.securityproj.entity.LoginAttempt;
import org.proj.securityproj.entity.User;
import org.proj.securityproj.repository.LoginAttemptRepository;
import org.proj.securityproj.repository.UserRepository;
import org.springframework.stereotype.Service;

import java.time.Instant;

@RequiredArgsConstructor
@Service
public class LoginAttemptService {
    private final LoginAttemptRepository loginAttemptRepository;
    private final UserRepository userRepository;

    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final long LOCK_TIME_DURATION_MINUTES = 15;

    @Transactional
    public void recordSuccessfulLogin(String email, HttpServletRequest request) {
        // Логування успішної спроби
        LoginAttempt attempt = new LoginAttempt();
        attempt.setEmail(email);
        attempt.setIpAddress(getClientIP(request));
        attempt.setSuccessful(true);
        attempt.setUserAgent(request.getHeader("User-Agent"));
        loginAttemptRepository.save(attempt);

        // Скидання лічильника невдалих спроб
        userRepository.findByEmail(email).ifPresent(user -> {
            if (user.getFailedLoginAttempts() > 0) {
                user.setFailedLoginAttempts(0);
                user.setAccountLocked(false);
                user.setAccountLockedUntil(null);
                userRepository.save(user);
            }
        });
    }

    @Transactional
    public void recordFailedLogin(String email, String reason, HttpServletRequest request) {
        System.out.println("=== Recording failed login for: " + email + " ===");

        // Логування невдалої спроби
        LoginAttempt attempt = new LoginAttempt();
        attempt.setEmail(email);
        attempt.setIpAddress(getClientIP(request));
        attempt.setSuccessful(false);
        attempt.setFailureReason(reason);
        attempt.setUserAgent(request.getHeader("User-Agent"));
        loginAttemptRepository.save(attempt);

        // Збільшення лічильника невдалих спроб
        userRepository.findByEmail(email).ifPresent(user -> {
            int attempts = user.getFailedLoginAttempts() + 1;
            user.setFailedLoginAttempts(attempts);

            System.out.println("Failed attempts count: " + attempts);

            if (attempts >= MAX_FAILED_ATTEMPTS) {
                user.setAccountLocked(true);
                user.setAccountLockedUntil(Instant.now().plusSeconds(LOCK_TIME_DURATION_MINUTES * 60));
                System.out.println("ACCOUNT LOCKED until: " + user.getAccountLockedUntil());
            }

            userRepository.save(user);
            System.out.println("User saved with " + user.getFailedLoginAttempts() + " failed attempts");
        });
    }

    public boolean isAccountLocked(String email) {
        return userRepository.findByEmail(email)
                .map(user -> {
                    if (user.isAccountLocked()) {
                        // Перевірка, чи минув час блокування
                        if (user.getAccountLockedUntil() != null &&
                                Instant.now().isAfter(user.getAccountLockedUntil())) {
                            // Розблокувати акаунт
                            user.setAccountLocked(false);
                            user.setAccountLockedUntil(null);
                            user.setFailedLoginAttempts(0);
                            userRepository.save(user);
                            return false;
                        }
                        return true;
                    }
                    return false;
                })
                .orElse(false);
    }

    public Instant getAccountLockedUntil(String email) {
        return userRepository.findByEmail(email)
                .map(User::getAccountLockedUntil)
                .orElse(null);
    }

    private String getClientIP(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0];
    }
}
