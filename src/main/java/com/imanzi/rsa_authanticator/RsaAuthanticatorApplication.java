package com.imanzi.rsa_authanticator;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;

@SpringBootApplication
@EntityScan(basePackages = "com.imanzi.rsa_authanticator.model")
public class RsaAuthanticatorApplication {

    public static void main(String[] args) {
        SpringApplication.run(RsaAuthanticatorApplication.class, args);
    }

}
