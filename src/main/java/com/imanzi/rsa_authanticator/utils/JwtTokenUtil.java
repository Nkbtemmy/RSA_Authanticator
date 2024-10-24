package com.imanzi.rsa_authanticator.utils;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.security.PrivateKey;
import java.util.Date;

@Component
@RequiredArgsConstructor
public class JwtTokenUtil {

    private final PrivateKey privateKey;

    public String generateToken(String subject) {
        return Jwts.builder()
                .setSubject(subject)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60)) // 1-hour expiration
                .signWith(privateKey, SignatureAlgorithm.RS256) // Sign with RSA private key
                .compact();
    }
}
