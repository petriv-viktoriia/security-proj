package org.proj.securityproj.service;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

@RequiredArgsConstructor
@Component
public class CustomAuthenticationHandler implements AuthenticationSuccessHandler, AuthenticationFailureHandler {
    private final LoginAttemptService loginAttemptService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication)
            throws IOException, ServletException {

        String email = authentication.getName();
        loginAttemptService.recordSuccessfulLogin(email, request);

        response.sendRedirect("/");
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception)
            throws IOException, ServletException {

        String email = request.getParameter("email");
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
            errorMessage = "Помилка автентифікації";
            loginAttemptService.recordFailedLogin(email, exception.getMessage(), request);
        }

        response.sendRedirect("/login?error=" +
                URLEncoder.encode(errorMessage, StandardCharsets.UTF_8));
    }
}