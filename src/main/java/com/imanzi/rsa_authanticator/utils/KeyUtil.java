package com.imanzi.rsa_authanticator.utils;

import java.io.InputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class KeyUtil {

    public static PrivateKey getPrivateKey(String filename) throws Exception {
        // Use class loader to load the private key file from resources/certificates
        ClassLoader classLoader = KeyUtil.class.getClassLoader();
        try (InputStream is = classLoader.getResourceAsStream("certificates/" + filename)) {
            if (is == null) {
                throw new IllegalArgumentException("Private key file not found: " + filename);
            }

            String key = new String(is.readAllBytes())
                    .replaceAll("-----BEGIN PRIVATE KEY-----", "")
                    .replaceAll("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");

            byte[] keyBytes = Base64.getDecoder().decode(key);

            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(spec);
        }
    }

    public static PublicKey getPublicKey(String filename) throws Exception {
        // Use class loader to load the public key file from resources/certificates
        ClassLoader classLoader = KeyUtil.class.getClassLoader();
        try (InputStream is = classLoader.getResourceAsStream("certificates/" + filename)) {
            if (is == null) {
                throw new IllegalArgumentException("Public key file not found: " + filename);
            }

            String key = new String(is.readAllBytes())
                    .replaceAll("-----BEGIN PUBLIC KEY-----", "")
                    .replaceAll("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s", "");

            byte[] keyBytes = Base64.getDecoder().decode(key);

            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(spec);
        }
    }
}
