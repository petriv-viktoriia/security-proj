package org.proj.securityproj.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.proj.securityproj.dto.UserRegisterDto;
import org.proj.securityproj.entity.User;
import org.proj.securityproj.repository.UserRepository;
import org.proj.securityproj.service.CaptchaService;
import org.proj.securityproj.service.LoginAttemptService;
import org.proj.securityproj.service.UserService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.time.Instant;

@RequiredArgsConstructor
@Controller
@RequestMapping
public class UserController {
    private final UserService userService;
    private final CaptchaService captchaService;
    private final UserRepository userRepository;
    private final LoginAttemptService loginAttemptService;

    @Value("${recaptcha.siteKey}")
    private String recaptchaSiteKey;

    @GetMapping("/register")
    public String showRegistrationForm(Model model) {
        model.addAttribute("user", new UserRegisterDto());
        model.addAttribute("recaptchaSiteKey", recaptchaSiteKey);
        return "register";
    }

    @PostMapping("/register")
    public String registerUser(
            @ModelAttribute("user") @Valid UserRegisterDto userDto,
            BindingResult bindingResult,
            @RequestParam("g-recaptcha-response") String captchaResponse,
            Model model) {

        if (bindingResult.hasErrors()) {
            model.addAttribute("recaptchaSiteKey", recaptchaSiteKey);
            return "register";
        }

        if (!captchaService.verifyCaptcha(captchaResponse)) {
            model.addAttribute("error", "Будь ласка, підтвердіть, що ви не робот");
            model.addAttribute("recaptchaSiteKey", recaptchaSiteKey);
            return "register";
        }

        try {
            userService.registerUser(userDto);
        } catch (IllegalArgumentException ex) {
            model.addAttribute("error", ex.getMessage());
            model.addAttribute("recaptchaSiteKey", recaptchaSiteKey);
            return "register";
        }

        return "redirect:/login?registered";
    }

    @GetMapping("/login")
    public String showLoginForm(
            @RequestParam(value = "email", required = false) String email,
            @RequestParam(value = "lockedUntil", required = false) Long lockedUntilParam,
            @RequestParam(value = "error", required = false) String error,
            Model model
    ) {
        if (email != null) {
            model.addAttribute("email", email);
        }

        if (error != null) {
            model.addAttribute("error", error);
        }

        if (lockedUntilParam != null && lockedUntilParam > System.currentTimeMillis()) {
            model.addAttribute("lockedUntil", lockedUntilParam);
            return "login";
        }

        if (email != null && loginAttemptService.isAccountLocked(email)) {
            Instant until = loginAttemptService.getAccountLockedUntil(email);
            if (until != null && until.toEpochMilli() > System.currentTimeMillis()) {
                model.addAttribute("lockedUntil", until.toEpochMilli());
            }
        }

        return "login";
    }

    @GetMapping("/")
    public String home(@AuthenticationPrincipal UserDetails userDetails, Model model) {
        if (userDetails == null) {
            return "redirect:/login";
        }

        model.addAttribute("email", userDetails.getUsername());
        return "home";
    }

    @GetMapping("/activate")
    public String activateUser(@RequestParam("token") String token, Model model) {
        User user = userRepository.findByActivationToken(token)
                .orElse(null);

        if (user == null || user.getTokenExpiresAt().isBefore(Instant.now())) {
            model.addAttribute("error", "Невірний або прострочений токен активації");
            return "activation-result";
        }

        user.setEnabled(true);
        user.setActivationToken(null);
        user.setTokenExpiresAt(null);
        userRepository.save(user);

        model.addAttribute("message", "Акаунт успішно активовано! Можете увійти.");
        return "activation-result";
    }

    @GetMapping("/forgot-password")
    public String showForgotPasswordForm() {
        return "forgot-password";
    }

    @PostMapping("/forgot-password")
    public String processForgotPassword(@RequestParam("email") String email, Model model) {
        try {
            userService.sendPasswordResetEmail(email);
            model.addAttribute("message", "Посилання на відновлення пароля відправлено на вашу електронну пошту");
        } catch (IllegalArgumentException ex) {
            model.addAttribute("error", ex.getMessage());
        }
        return "forgot-password";
    }

    @GetMapping("/reset-password")
    public String showResetPasswordForm(@RequestParam("token") String token, Model model) {
        model.addAttribute("token", token);
        return "reset-password";
    }

    @PostMapping("/reset-password")
    public String processResetPassword(
            @RequestParam("token") String token,
            @RequestParam("password") String password,
            @RequestParam("confirmPassword") String confirmPassword,
            Model model
    ) {
        if (!password.equals(confirmPassword)) {
            model.addAttribute("error", "Паролі не співпадають");
            model.addAttribute("token", token);
            return "reset-password";
        }

        try {
            userService.resetPassword(token, password);
            model.addAttribute("message", "Пароль успішно змінено! Можете увійти за посиланням нижче.");
            model.addAttribute("token", token);
            return "reset-password";
        } catch (IllegalArgumentException ex) {
            model.addAttribute("error", ex.getMessage());
            model.addAttribute("token", token);
            return "reset-password";
        }
    }

    @GetMapping("/access-denied")
    public String accessDenied() {
        return "access-denied";
    }
}
