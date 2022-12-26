package com.jakublesko.jwtsecurity;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.util.function.Predicate;

/**
 * https://dev.to/kubadlo/spring-security-with-jwt-3j76
 *
 */
@SpringBootApplication
public class SpringSecurityJwtExampleApplication {

    public static void main(String[] args) {

        SpringApplication.run(SpringSecurityJwtExampleApplication.class, args);
    }
}

