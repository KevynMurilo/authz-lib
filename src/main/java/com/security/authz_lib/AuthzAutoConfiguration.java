package com.security.authz_lib;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AuthzAutoConfiguration {

    @Bean("authz")
    public Authz authz() {
        return new Authz();
    }
}
