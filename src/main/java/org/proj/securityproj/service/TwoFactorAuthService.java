package org.proj.securityproj.service;

import dev.samstevens.totp.code.*;
import org.springframework.context.annotation.Lazy;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import org.proj.securityproj.entity.User;
import org.proj.securityproj.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

@Service
public class TwoFactorAuthService {

    private final UserRepository userRepository;
    private PasswordEncoder passwordEncoder;

    public TwoFactorAuthService(UserRepository userRepository, @Lazy PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    private final SecretGenerator secretGenerator = new DefaultSecretGenerator();
    private final QrGenerator qrGenerator = new ZxingPngQrGenerator();
    private final TimeProvider timeProvider = new SystemTimeProvider();
    private final CodeGenerator codeGenerator = new DefaultCodeGenerator();
    private final CodeVerifier verifier = new DefaultCodeVerifier(codeGenerator, timeProvider);

    public String generateSecret() {
        return secretGenerator.generate();
    }

    public String generateQrCodeImageUri(String email, String secret) {
        QrData data = new QrData.Builder()
                .label(email)
                .secret(secret)
                .issuer("SecurityProject")
                .algorithm(HashingAlgorithm.SHA1)
                .digits(6)
                .period(30)
                .build();

        try {
            byte[] imageData = qrGenerator.generate(data);
            String mimeType = qrGenerator.getImageMimeType();
            return "data:" + mimeType + ";base64," + Base64.getEncoder().encodeToString(imageData);
        } catch (Exception e) {
            throw new RuntimeException("Помилка генерації QR коду", e);
        }
    }

    public boolean verifyCode(String secret, String code) {
        return verifier.isValidCode(secret, code);
    }

    public List<String> enable2FA(String email, String verificationCode) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("Користувача не знайдено"));

        if (user.getTwoFactorSecret() == null) {
            throw new IllegalArgumentException("Спочатку ініціалізуйте 2FA");
        }

        if (!verifyCode(user.getTwoFactorSecret(), verificationCode)) {
            throw new IllegalArgumentException("Невірний код підтвердження");
        }

        user.setTwoFactorEnabled(true);

        List<String> backupCodes = generateBackupCodes();
        user.setBackupCodes(encryptBackupCodes(backupCodes));

        userRepository.save(user);

        return backupCodes;
    }

    public void disable2FA(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("Користувача не знайдено"));

        user.setTwoFactorEnabled(false);
        user.setTwoFactorSecret(null);
        user.setBackupCodes(new ArrayList<>());

        userRepository.save(user);
    }

    public String initialize2FA(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("Користувача не знайдено"));

        String secret = generateSecret();
        user.setTwoFactorSecret(secret);
        userRepository.save(user);

        return secret;
    }

    private List<String> generateBackupCodes() {
        List<String> codes = new ArrayList<>();
        SecureRandom random = new SecureRandom();

        for (int i = 0; i < 10; i++) {
            int code = 100000 + random.nextInt(900000);
            codes.add(String.valueOf(code));
        }

        return codes;
    }

    private List<String> encryptBackupCodes(List<String> codes) {
        List<String> encrypted = new ArrayList<>();
        for (String code : codes) {
            encrypted.add(passwordEncoder.encode(code));
        }
        return encrypted;
    }

    public boolean verifyBackupCode(User user, String code) {
        for (String encryptedCode : user.getBackupCodes()) {
            if (passwordEncoder.matches(code, encryptedCode)) {
                user.getBackupCodes().remove(encryptedCode);
                userRepository.save(user);
                return true;
            }
        }
        return false;
    }

    public boolean is2FAEnabled(String email) {
        return userRepository.findByEmail(email)
                .map(User::isTwoFactorEnabled)
                .orElse(false);
    }
}
