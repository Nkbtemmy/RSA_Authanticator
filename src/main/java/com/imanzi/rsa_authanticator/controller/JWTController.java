package com.imanzi.rsa_authanticator.controller;

import com.imanzi.rsa_authanticator.utils.JwtTokenUtil;
import com.imanzi.rsa_authanticator.utils.JwtTokenVerifier;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.PrivateKey;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/marketplace/auths/jwt")
@RequiredArgsConstructor
public class JWTController {

    private final JwtTokenUtil jwtTokenUtil;
    private final JwtTokenVerifier jwtTokenVerifier;

    /**
     * Endpoint to generate a JWT token using a private key.
     * Example: POST /api/v1/jwt/generate?username=example
     */
    @PostMapping("/generate")
    public ResponseEntity<Map<String, String>> generateToken(@RequestParam String username) {
        String token = jwtTokenUtil.generateToken(username);
        return ResponseEntity.ok(Map.of("token", token));
    }

    /**
     * Endpoint to verify a JWT token using a public key.
     * Example: POST /api/v1/jwt/verify
     */
    @PostMapping("/verify")
    public ResponseEntity<?> verifyToken(@RequestBody Map<String, String> request) {
        String token = request.get("token");
        try {
            var claims = jwtTokenVerifier.verifyToken(token);
            return ResponseEntity.ok(claims);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Invalid token");
        }
    }
}
