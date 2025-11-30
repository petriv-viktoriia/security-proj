package org.proj.securityproj.service;

import lombok.RequiredArgsConstructor;
import org.proj.securityproj.dto.CustomOAuth2User;
import org.proj.securityproj.entity.User;
import org.proj.securityproj.repository.UserRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;


@RequiredArgsConstructor
@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {
    private final UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oauth2User = super.loadUser(userRequest);
        String email = oauth2User.getAttribute("email");

        if (email == null) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error("invalid_user_info", "Email not found from OAuth2 provider", null)
            );
        }

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new OAuth2AuthenticationException(
                        new OAuth2Error("user_not_found", "Користувача з email " + email + " не знайдено.", null)
                ));

        if (!user.isEnabled()) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error("user_not_activated", "Акаунт не активовано.", null)
            );
        }

        String accessToken = userRequest.getAccessToken().getTokenValue();
        user.setOauthAccessToken(accessToken);

        if (userRequest.getAccessToken().getExpiresAt() != null) {
            user.setOauthTokenExpiresAt(userRequest.getAccessToken().getExpiresAt());
        }

        userRepository.save(user);
        return new CustomOAuth2User(oauth2User, user.getEmail(), user.getPassword(), user.getRole());
    }
}
