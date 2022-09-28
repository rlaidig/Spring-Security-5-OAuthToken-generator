package com.example.demo;

import feign.Feign;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.client.AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.InMemoryReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;

import java.util.Objects;

@Configuration
@ConditionalOnClass(Feign.class)
@ConditionalOnProperty(value = "security.oauth2.client.client-id")
public class ReactiveOauth2ClientConfiguration {
    @Bean
    ReactiveClientRegistrationRepository wguClientRegistrations(
            @Value("wgu") String id,
            @Value("${security.oauth2.client.access-token-uri}") String accessTokenUri,
            @Value("${security.oauth2.client.client-id}") String clientId,
            @Value("${security.oauth2.client.client-secret}") String clientSecret,
            @Value("${security.oauth2.client.scope:#{null}}") String scope,
            @Value("${security.oauth2.client.authorization-grant-type:#{null}}") AuthorizationGrantType authorizationGrantType,
            @Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri:#{null}}") String jwkSetUri
    ) {
        ClientRegistration.Builder wguRegistration = ClientRegistration
                .withRegistrationId(id)
                .tokenUri(accessTokenUri)
                .clientId(clientId)
                .clientSecret(clientSecret)
                .authorizationGrantType(authorizationGrantType == null ? AuthorizationGrantType.CLIENT_CREDENTIALS : authorizationGrantType);
        ;
        if (scope != null)
            wguRegistration.scope(scope);
        if (jwkSetUri != null)
            wguRegistration.jwkSetUri(jwkSetUri);

        ClientRegistration wugRegistration = wguRegistration.build();

        return new InMemoryReactiveClientRegistrationRepository(wugRegistration);
    }

    @Bean
    AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager authorizedClientManager(ReactiveClientRegistrationRepository wguClientRegistrations) {
        InMemoryReactiveOAuth2AuthorizedClientService clientService = new InMemoryReactiveOAuth2AuthorizedClientService(wguClientRegistrations);
        return new AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager(wguClientRegistrations, clientService);
    }

    /**
     * @see https://github.com/spring-projects/spring-security/issues/8649#issuecomment-650326214
     * @see https://www.rfc-editor.org/rfc/rfc6749#section-4.4.2
     * @see https://www.rfc-editor.org/rfc/rfc6749#section-3.2.1
     * @see https://docs.spring.io/spring-security/site/docs/5.3.2.RELEASE/reference/html5/#customizing-the-access-token-response-3
     * @see https://gist.github.com/loesak/d042f545a57bb6e875347542b1eb1793
     *
     * @param authorizedClientManager
     */
    private static final void sample(AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager authorizedClientManager) {
        final Authentication ANONYMOUS_AUTHENTICATION = new AnonymousAuthenticationToken(
                "anonymous", "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_FEIGN_CLIENT"));

        OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.withClientRegistrationId("wgu")
                .principal(ANONYMOUS_AUTHENTICATION)
                .build();
        OAuth2AuthorizedClient authorizedClient = authorizedClientManager.authorize(authorizeRequest).block();

        OAuth2AccessToken accessToken = Objects.requireNonNull(authorizedClient.getAccessToken());
    }
}
