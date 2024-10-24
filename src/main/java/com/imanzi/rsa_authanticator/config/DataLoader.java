package com.imanzi.rsa_authanticator.config;


import com.imanzi.rsa_authanticator.model.User;
import com.imanzi.rsa_authanticator.model.enums.Role;
import com.imanzi.rsa_authanticator.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;

@Configuration
@RequiredArgsConstructor
public class DataLoader {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Bean
    public CommandLineRunner loadData() {
        return args -> {
            if (userRepository.count() == 0) {
                User admin = User.builder()
                        .firstname("Admin")
                        .lastname("User")
                        .username("admin")
                        .password(passwordEncoder.encode("adminPass"))
                        .email("admin@example.com")
                        .emailVerified(true)
                        .role(Role.ADMIN)
                        .build();

                User buyer = User.builder()
                        .firstname("Buyer")
                        .lastname("User")
                        .username("buyer")
                        .password(passwordEncoder.encode("buyerPass"))
                        .email("buyer@example.com")
                        .emailVerified(true)
                        .role(Role.BUYER)
                        .build();

                User seller = User.builder()
                        .firstname("Seller")
                        .lastname("User")
                        .username("seller")
                        .password(passwordEncoder.encode("sellerPass"))
                        .email("seller@example.com")
                        .emailVerified(true)
                        .role(Role.SELLER)
                        .build();

                userRepository.saveAll(List.of(admin, buyer, seller));
            }
        };
    }
}
