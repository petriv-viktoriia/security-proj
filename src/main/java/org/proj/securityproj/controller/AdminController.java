package org.proj.securityproj.controller;

import lombok.RequiredArgsConstructor;
import org.proj.securityproj.entity.LoginAttempt;
import org.proj.securityproj.repository.LoginAttemptRepository;
import org.proj.securityproj.service.UserService;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@RequiredArgsConstructor
@Controller
@RequestMapping("/admin")
public class AdminController {
    private final LoginAttemptRepository loginAttemptRepository;
    private final UserService userService;

    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @GetMapping("/login-attempts")
    public String viewLoginAttempts(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            Model model) {

        Pageable pageable = PageRequest.of(page, size);
        Page<LoginAttempt> attempts = loginAttemptRepository.findAllByOrderByAttemptTimeDesc(pageable);

        model.addAttribute("attempts", attempts);
        model.addAttribute("currentPage", page);
        model.addAttribute("totalPages", attempts.getTotalPages());

        return "login-attempts";
    }

    @PutMapping("make-admin")
    public String makeAdmin(@RequestParam String email) {
        try {
            userService.assignAdminRole(email);
            return "Роль ADMIN призначено користувачу: " + email;
        } catch (Exception e) {
            return "Помилка: " + e.getMessage();
        }
    }
}