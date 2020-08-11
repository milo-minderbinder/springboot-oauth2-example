package co.insecurity.example.springboot.oauth2.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.HashMap;
import java.util.Map;


@SpringBootApplication
@RestController
public class DemoApplication {

    @RequestMapping("/user")
    public Principal user(Principal principal) {
        return principal;
    }

    @RequestMapping("/authentication")
    public Map<String, Object> getAuthentication() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Map<String, Object> result = new HashMap<>();
        result.put("authentication-class", authentication.getClass().getCanonicalName());
        result.put("authentication", authentication);
        return result;
    }

    @RequestMapping("/authorizedClient")
    public OAuth2AuthorizedClient getAuthorizedClient(@RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient authorizedClient) {
        return authorizedClient;
    }

    @RequestMapping("/getOAuth2User")
    public OAuth2User getOAuth2User(@AuthenticationPrincipal OAuth2User oAuth2User) {
        return oAuth2User;
    }

    @RequestMapping("/getOIDCUser")
    public OidcUser getOIDCUser(@AuthenticationPrincipal OidcUser user) {
        return user;
    }

    @RequestMapping("/getAccessToken")
    public OAuth2AccessToken getAccessToken(@RegisteredOAuth2AuthorizedClient("okta") OAuth2AuthorizedClient authorizedClient) {
        return authorizedClient.getAccessToken();
    }

    @RequestMapping("/getOidcIdToken")
    public OidcIdToken getOidcIdToken(@AuthenticationPrincipal OidcUser user) {
        return user.getIdToken();
    }

    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }
}
