package org.proj.securityproj.service;

import lombok.RequiredArgsConstructor;
import org.proj.securityproj.dto.CustomUserDetails;
import org.proj.securityproj.entity.User;
import org.proj.securityproj.repository.UserRepository;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Collections;

@RequiredArgsConstructor
@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("Користувача з таким email не існує"));

        boolean accountNonLocked = true;
        if (user.isAccountLocked() && user.getAccountLockedUntil() != null) {
            accountNonLocked = Instant.now().isAfter(user.getAccountLockedUntil());

            if (accountNonLocked) {
                user.setAccountLocked(false);
                user.setAccountLockedUntil(null);
                user.setFailedLoginAttempts(0);
                userRepository.save(user);
            }
        }

        String roleName = "ROLE_" + user.getRole().name();

        return org.springframework.security.core.userdetails.User.builder()
                .username(user.getEmail())
                .password(user.getPassword())
                .authorities(Collections.singletonList(new SimpleGrantedAuthority(roleName)))
                .accountLocked(!accountNonLocked)
                .disabled(!user.isEnabled())
                .build();
    }
}
