package com.iammahbubalam.cp_auth_service.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Service
@Slf4j
public class SecurityKeyManager {

    @Value("${app.jwt.rsa.private-key-path}")
    private String privateKeyPath;

    @Value("${app.jwt.rsa.public-key-path}")
    private String publicKeyPath;

    @Cacheable(value = "publicKeyCache", key = "'rsa-public-key'")
    public PublicKey getPublicKey() {
        log.info("Loading public key from: {}", publicKeyPath);
        try {
            ClassPathResource resource = new ClassPathResource(publicKeyPath);
            String publicKeyContent = new String(Files.readAllBytes(resource.getFile().toPath()))
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s", "");

            byte[] decoded = Base64.getDecoder().decode(publicKeyContent);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            return keyFactory.generatePublic(spec);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            log.error("Failed to load public key from: {}", publicKeyPath, e);
            throw new RuntimeException("Failed to load RSA public key", e);
        }
    }

    @Cacheable(value = "publicKeyCache", key = "'rsa-private-key'")
    public PrivateKey getPrivateKey() {
        log.info("Loading private key from: {}", privateKeyPath);
        try {
            ClassPathResource resource = new ClassPathResource(privateKeyPath);
            String privateKeyContent = new String(Files.readAllBytes(resource.getFile().toPath()))
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");

            byte[] decoded = Base64.getDecoder().decode(privateKeyContent);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            return keyFactory.generatePrivate(spec);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            log.error("Failed to load private key from: {}", privateKeyPath, e);
            throw new RuntimeException("Failed to load RSA private key", e);
        }
    }
}
