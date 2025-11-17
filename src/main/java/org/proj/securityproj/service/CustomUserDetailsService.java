package org.proj.securityproj.service;

import lombok.RequiredArgsConstructor;
import org.proj.securityproj.dto.CustomUserDetails;
import org.proj.securityproj.entity.User;
import org.proj.securityproj.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("Користувача з таким email не існує"));
        return new CustomUserDetails(user);
    }
}
