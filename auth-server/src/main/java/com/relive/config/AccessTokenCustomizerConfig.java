package com.relive.config;

import com.relive.entity.Permission;
import com.relive.repository.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.util.stream.Collectors;

@Configuration(proxyBeanMethods = false)
public class AccessTokenCustomizerConfig {

    @Autowired
    RoleRepository roleRepository;

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return (context) -> {
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                context.getClaims().claims(claim -> {
                    claim.put("authorities", roleRepository.findByRoleCode(context.getPrincipal().getAuthorities().stream()
                            .map(GrantedAuthority::getAuthority).findFirst().orElse("ROLE_OPERATION"))
                            .getPermissions().stream().map(Permission::getPermissionCode).collect(Collectors.toSet()));
                });
            }
        };
    }
}
