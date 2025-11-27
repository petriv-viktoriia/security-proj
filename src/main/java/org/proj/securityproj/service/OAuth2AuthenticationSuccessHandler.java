package org.proj.securityproj.service;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.proj.securityproj.entity.User;
import org.proj.securityproj.repository.UserRepository;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class OAuth2AuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final TwoFactorAuthService twoFactorAuthService;
    private final UserRepository userRepository;
    private final LoginAttemptService loginAttemptService;

    public OAuth2AuthenticationSuccessHandler(
            @Lazy TwoFactorAuthService twoFactorAuthService,
            UserRepository userRepository,
            LoginAttemptService loginAttemptService) {
        this.twoFactorAuthService = twoFactorAuthService;
        this.userRepository = userRepository;
        this.loginAttemptService = loginAttemptService;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
        String email = oauth2User.getAttribute("email");

        if (email == null) {
            response.sendRedirect("/login?error=invalid_oauth");
            return;
        }

        User user = userRepository.findByEmail(email).orElse(null);

        if (user == null) {
            response.sendRedirect("/login?error=user_not_found");
            return;
        }

        if (user.isTwoFactorEnabled()) {
            HttpSession session = request.getSession();
            session.setAttribute("2FA_USER", email);
            session.setAttribute("2FA_AUTH", authentication);

            response.sendRedirect("/2fa/verify");
            return;
        }

        loginAttemptService.recordSuccessfulLogin(email, request);
        response.sendRedirect("/");
    }
}