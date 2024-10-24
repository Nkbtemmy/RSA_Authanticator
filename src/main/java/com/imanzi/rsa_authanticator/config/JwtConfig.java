package com.imanzi.rsa_authanticator.config;

import com.imanzi.rsa_authanticator.utils.JwtTokenUtil;
import com.imanzi.rsa_authanticator.utils.JwtTokenVerifier;
import com.imanzi.rsa_authanticator.utils.KeyUtil;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class JwtConfig {

    @Bean
    public JwtTokenVerifier jwtTokenVerifier() throws Exception {
        return new JwtTokenVerifier(KeyUtil.getPublicKey("public_key.pem"));
    }

    @Bean
    public JwtTokenUtil jwtTokenUtil() throws Exception {
        return new JwtTokenUtil(KeyUtil.getPrivateKey("private_key.pem"));
    }
}
