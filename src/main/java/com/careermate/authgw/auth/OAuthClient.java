package com.careermate.authgw.auth;

import java.util.Set;

public record OAuthClient(
        String clientId,
        String clientName,
        String authMethod,
        String jwksUri,
        Set<String> allowedGrantTypes,
        Set<String> allowedAudiences,
        Set<String> allowedScopes,
        String status) {
}
