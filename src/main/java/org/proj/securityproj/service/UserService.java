package org.proj.securityproj.service;

import lombok.RequiredArgsConstructor;
import org.proj.securityproj.dto.UserRegisterDto;
import org.proj.securityproj.entity.User;
import org.proj.securityproj.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

@RequiredArgsConstructor
@Service
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JavaMailSender mailSender;

    @Value("${spring.mail.username}")
    private String emailUsername;

    @Value("${spring.mail.password}")
    private String emailPassword;

    public void registerUser(UserRegisterDto dto) {
        if (userRepository.existsByEmail(dto.getEmail())) {
            throw new IllegalArgumentException("Email вже використовується");
        }

        if (!dto.getPassword().equals(dto.getConfirmPassword())) {
            throw new IllegalArgumentException("Паролі не співпадають");
        }

        User user = new User();
        user.setEmail(dto.getEmail());
        user.setPassword(passwordEncoder.encode(dto.getPassword()));

        user.setActivationToken(UUID.randomUUID().toString());
        user.setTokenExpiresAt(Instant.now().plusSeconds(24 * 3600));
        user.setEnabled(false);

        userRepository.save(user);
        sendActivationEmail(user);
    }

    private void sendActivationEmail(User user) {
        System.out.println("EMAIL_USERNAME: " + emailUsername);
        System.out.println("EMAIL_PASSWORD length: " +
                (emailPassword != null ? emailPassword.length() : "null"));
        System.out.println("EMAIL_PASSWORD (masked): " +
                (emailPassword != null ? emailPassword.substring(0, 4) + "..." : "null"));

        String activationLink = "http://localhost:5173/activate?token=" + user.getActivationToken();

        SimpleMailMessage mailMessage = new SimpleMailMessage();
        mailMessage.setTo(user.getEmail());
        mailMessage.setSubject("Активація облікового запису");
        mailMessage.setText("Привіт!\n\nБудь ласка, активуйте ваш акаунт, перейшовши за посиланням:\n"
                + activationLink
                + "\n\nЦе посилання дійсне 24 години.");

        mailSender.send(mailMessage);
    }
}
