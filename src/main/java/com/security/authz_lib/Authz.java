package com.security.authz_lib;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Arrays;
import java.util.UUID;

public class Authz {

    private Authentication getAuthentication() {
        return SecurityContextHolder.getContext().getAuthentication();
    }

    public boolean hasAnyRole(String... roles) {
        Authentication authentication = getAuthentication();
        if (authentication == null || authentication.getAuthorities() == null) return false;

        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(auth -> Arrays.stream(roles).anyMatch(role -> auth.equalsIgnoreCase("ROLE_" + role)));
    }

    public boolean isSelf(UUID id) {
        Authentication authentication = getAuthentication();
        if (authentication == null || authentication.getPrincipal() == null) return false;

        Object principal = authentication.getPrincipal();
        try {
            var field = principal.getClass().getDeclaredField("id");
            field.setAccessible(true);
            UUID userId = (UUID) field.get(principal);
            return id.equals(userId);
        } catch (Exception e) {
            return false;
        }
    }

    public boolean isSelfOrHasAnyRole(UUID id, String... roles) {
        return isSelf(id) || hasAnyRole(roles);
    }
}
