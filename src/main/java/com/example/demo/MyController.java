package com.example.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.client.AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MyController {
    private static final Authentication ANONYMOUS_AUTHENTICATION = new AnonymousAuthenticationToken(
            "anonymous", "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_FEIGN_CLIENT"));
    AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager authorizedClientManager;

    @Autowired
    MyController(AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager authorizedClientManager){
        this.authorizedClientManager = authorizedClientManager;
    }

    @RequestMapping(value="/", method=RequestMethod.GET)
    public OAuth2AccessToken showMap(){

        OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
                .withClientRegistrationId("wgu")
                .principal(ANONYMOUS_AUTHENTICATION)
                .build();

        OAuth2AuthorizedClient authorizedClient = authorizedClientManager.authorize(authorizeRequest).block();

        return authorizedClient.getAccessToken();
    }
}
