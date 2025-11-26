package org.proj.securityproj.service;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class OAuth2LoginFailureHandler implements AuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {

        String errorMessage = "oauth_error";

        // Перевіряємо, чи це OAuth2AuthenticationException
        if (exception instanceof OAuth2AuthenticationException oauth2Exception) {
            String errorCode = oauth2Exception.getError().getErrorCode();

            // Отримуємо детальне повідомлення
            if ("user_not_found".equals(errorCode)) {
                errorMessage = "user_not_found";
            } else if ("user_not_activated".equals(errorCode)) {
                errorMessage = "notActivated";
            } else if ("invalid_user_info".equals(errorCode)) {
                errorMessage = "invalid_oauth";
            }
        }

        response.sendRedirect("/login?" + errorMessage);
    }
}