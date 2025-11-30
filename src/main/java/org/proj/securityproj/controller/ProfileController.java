package org.proj.securityproj.controller;

import lombok.RequiredArgsConstructor;
import org.proj.securityproj.entity.Role;
import org.proj.securityproj.entity.User;
import org.proj.securityproj.repository.UserRepository;
import org.proj.securityproj.service.TwoFactorAuthService;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.List;

@RequiredArgsConstructor
@Controller
@RequestMapping("/profile")
public class ProfileController {

    private final TwoFactorAuthService twoFactorAuthService;
    private final UserRepository userRepository;

    @GetMapping
    public String showProfile(@AuthenticationPrincipal UserDetails userDetails, Model model) {
        User user = userRepository.findByEmail(userDetails.getUsername())
                .orElseThrow(() -> new IllegalArgumentException("Користувача не знайдено"));

        model.addAttribute("user", user);
        model.addAttribute("twoFactorEnabled", user.isTwoFactorEnabled());
        model.addAttribute("isAdmin", user.getRole().equals(Role.ADMIN));
        return "profile";
    }

    @GetMapping("/2fa/setup")
    public String setup2FA(@AuthenticationPrincipal UserDetails userDetails, Model model) {
        String email = userDetails.getUsername();

        String secret = twoFactorAuthService.initialize2FA(email);
        String qrCodeUri = twoFactorAuthService.generateQrCodeImageUri(email, secret);

        model.addAttribute("qrCode", qrCodeUri);
        model.addAttribute("secret", secret);
        model.addAttribute("email", email);

        return "2fa-setup";
    }

    @PostMapping("/2fa/enable")
    public String enable2FA(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam("code") String code,
            RedirectAttributes redirectAttributes,
            Model model) {

        try {
            String email = userDetails.getUsername();
            List<String> backupCodes = twoFactorAuthService.enable2FA(email, code);

            model.addAttribute("backupCodes", backupCodes);
            model.addAttribute("message", "2FA успішно увімкнено!");

            return "2fa-backup-codes";
        } catch (IllegalArgumentException e) {
            redirectAttributes.addFlashAttribute("error", e.getMessage());
            return "redirect:/profile/2fa/setup";
        }
    }

    @PostMapping("/2fa/disable")
    public String disable2FA(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam("code") String code,
            @RequestParam(value = "useBackupCode", required = false, defaultValue = "false") boolean useBackupCode,
            RedirectAttributes redirectAttributes) {

        try {
            String email = userDetails.getUsername();
            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new IllegalArgumentException("Користувача не знайдено"));

            boolean isValid;

            if (useBackupCode) {
                isValid = twoFactorAuthService.verifyBackupCode(user, code);
            } else {
                isValid = twoFactorAuthService.verifyCode(user.getTwoFactorSecret(), code);
            }

            if (!isValid) {
                throw new IllegalArgumentException("Невірний код");
            }

            twoFactorAuthService.disable2FA(email);
            redirectAttributes.addFlashAttribute("message", "2FA успішно вимкнено");

        } catch (IllegalArgumentException e) {
            redirectAttributes.addFlashAttribute("error", e.getMessage());
        }

        return "redirect:/profile";
    }
}
