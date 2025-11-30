package org.proj.securityproj.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.proj.securityproj.entity.User;
import org.proj.securityproj.repository.UserRepository;
import org.proj.securityproj.service.LoginAttemptService;
import org.proj.securityproj.service.TwoFactorAuthService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@RequiredArgsConstructor
@Controller
@RequestMapping("/2fa")
public class TwoFactorAuthController {
    private final TwoFactorAuthService twoFactorAuthService;
    private final UserRepository userRepository;
    private final LoginAttemptService loginAttemptService;

    @GetMapping("/verify")
    public String show2FAVerification(HttpSession session, Model model) {
        String email = (String) session.getAttribute("2FA_USER");

        if (email == null) {
            return "redirect:/login";
        }

        model.addAttribute("email", email);
        return "2fa-verify";
    }

    @PostMapping("/verify")
    public String verify2FA(
            @RequestParam("code") String code,
            @RequestParam(value = "useBackupCode", required = false, defaultValue = "false") boolean useBackupCode,
            HttpSession session,
            HttpServletRequest request,
            RedirectAttributes redirectAttributes) {

        String email = (String) session.getAttribute("2FA_USER");
        Authentication auth = (Authentication) session.getAttribute("2FA_AUTH");

        if (email == null || auth == null) {
            redirectAttributes.addFlashAttribute("error", "Сесія закінчилася. Увійдіть знову.");
            return "redirect:/login";
        }

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("Користувача не знайдено"));

        boolean isValid;

        if (useBackupCode) {
            isValid = twoFactorAuthService.verifyBackupCode(user, code);
        } else {
            isValid = twoFactorAuthService.verifyCode(user.getTwoFactorSecret(), code);
        }

        if (isValid) {
            SecurityContextHolder.getContext().setAuthentication(auth);
            loginAttemptService.recordSuccessfulLogin(email, request);
            session.removeAttribute("2FA_USER");
            session.removeAttribute("2FA_AUTH");

            return "redirect:/";
        } else {
            loginAttemptService.recordFailedLogin(email, "Invalid 2FA code", request);
            redirectAttributes.addFlashAttribute("error", "Невірний код. Спробуйте ще раз.");
            return "redirect:/2fa/verify";
        }
    }
}