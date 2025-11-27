package org.proj.securityproj.service;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.proj.securityproj.entity.User;
import org.proj.securityproj.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

@Component
public class CustomAuthenticationHandler implements AuthenticationSuccessHandler, AuthenticationFailureHandler {

    private static final Logger log = LoggerFactory.getLogger(CustomAuthenticationHandler.class);

    private final LoginAttemptService loginAttemptService;
    private final UserRepository userRepository;

    public CustomAuthenticationHandler(
            LoginAttemptService loginAttemptService,
            UserRepository userRepository) {
        this.loginAttemptService = loginAttemptService;
        this.userRepository = userRepository;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication)
            throws IOException, ServletException {

        String email = authentication.getName();
        log.info("=== Authentication Success Handler ===");
        log.info("Email: {}", email);
        log.info("Authentication type: {}", authentication.getClass().getName());

        User user = userRepository.findByEmail(email).orElse(null);

        if (user == null) {
            log.error("User not found in database: {}", email);
            response.sendRedirect("/login?error=user_not_found");
            return;
        }

        if (user.isTwoFactorEnabled()) {
            SecurityContextHolder.clearContext();

            HttpSession session = request.getSession();
            session.setAttribute("2FA_USER", email);
            session.setAttribute("2FA_AUTH", authentication);

            response.sendRedirect("/2fa/verify");
            return;
        }

        loginAttemptService.recordSuccessfulLogin(email, request);
        response.sendRedirect("/");
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception)
            throws IOException, ServletException {

        String email = request.getParameter("email");
        log.error("=== Authentication Failure ===");
        log.error("Email: {}", email);
        log.error("Exception: {}", exception.getClass().getName());
        log.error("Message: {}", exception.getMessage());

        String errorMessage;

        if (exception instanceof LockedException) {
            Instant lockedUntil = loginAttemptService.getAccountLockedUntil(email);
            errorMessage = "Акаунт заблоковано через багато невдалих спроб входу. Спробуйте пізніше.";
            loginAttemptService.recordFailedLogin(email, "Account locked", request);
        } else if (exception instanceof DisabledException) {
            errorMessage = "Акаунт не активовано. Перевірте свою електронну пошту.";
            loginAttemptService.recordFailedLogin(email, "Account not activated", request);
        } else if (exception instanceof BadCredentialsException) {
            errorMessage = "Невірний email або пароль";
            loginAttemptService.recordFailedLogin(email, "Bad credentials", request);
        } else {
            errorMessage = "Помилка аутентифікації";
            loginAttemptService.recordFailedLogin(email, exception.getMessage(), request);
        }

        response.sendRedirect("/login?error=" +
                URLEncoder.encode(errorMessage, StandardCharsets.UTF_8));
    }
}