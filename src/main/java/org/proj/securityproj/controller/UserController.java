package org.proj.securityproj.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.proj.securityproj.dto.UserRegisterDto;
import org.proj.securityproj.service.CaptchaService;
import org.proj.securityproj.service.UserService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

@RequiredArgsConstructor
@Controller
@RequestMapping
public class UserController {
    private final UserService userService;
    private final CaptchaService captchaService;

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
    public String showLoginForm(Model model) {
        model.addAttribute("error", "");
        return "login";
    }

    @GetMapping
    public String home(@AuthenticationPrincipal UserDetails userDetails, Model model) {
        // передаємо email користувача на сторінку
        model.addAttribute("email", userDetails.getUsername());
        model.addAttribute("password", userDetails.getPassword());
        return "home"; // home.html
    }
}
