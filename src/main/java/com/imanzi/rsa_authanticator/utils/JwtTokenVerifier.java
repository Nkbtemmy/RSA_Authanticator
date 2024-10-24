package com.imanzi.rsa_authanticator.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import java.security.PublicKey;

public class JwtTokenVerifier {

    private final PublicKey publicKey;

    public JwtTokenVerifier(PublicKey publicKey) {
        this.publicKey = publicKey;
    }


    public Claims verifyToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(publicKey) // Use the RSA public key
                .build()
                .parseClaimsJws(token)
                .getBody(); // Return the claims (payload) of the JWT
    }

    public Claims verifyJWTToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(publicKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}

