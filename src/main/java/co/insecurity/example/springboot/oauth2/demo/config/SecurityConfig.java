package co.insecurity.example.springboot.oauth2.demo.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@EnableConfigurationProperties(MyOAuth2ResourceServerProperties.class)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private final ClientRegistrationRepository clientRegistrationRepository;
    private final OAuth2ResourceServerProperties oAuth2ResourceServerProperties;
    private final MyOAuth2ResourceServerProperties myOAuth2ResourceServerProperties;

    @Autowired
    public SecurityConfig(MyOAuth2ResourceServerProperties myOAuth2ResourceServerProperties,
                          ClientRegistrationRepository clientRegistrationRepository,
                          OAuth2ResourceServerProperties oAuth2ResourceServerProperties) {
        this.myOAuth2ResourceServerProperties = myOAuth2ResourceServerProperties;
        this.clientRegistrationRepository = clientRegistrationRepository;
        this.oAuth2ResourceServerProperties = oAuth2ResourceServerProperties;
    }

    @Bean
    public OAuth2TokenValidator<Jwt> jwtValidator() {
        final String resourceServerIssuerURI = this.oAuth2ResourceServerProperties.getJwt().getIssuerUri();
        OAuth2TokenValidator<Jwt> validator = new DelegatingOAuth2TokenValidator<>(
                // Validates issuer (iss) and
                JwtValidators.createDefaultWithIssuer(resourceServerIssuerURI),
                (token -> {
                    final String errorCode = "invalid_token";
                    final String errorURI = "https://tools.ietf.org/html/rfc6750#section-3.1";
                    List<OAuth2Error> errors = new ArrayList<>();

                    if (!this.myOAuth2ResourceServerProperties.getAllowedAudienceValues().containsAll(token.getAudience())) {
                        String errorMessage = String.format("audience (aud) claim does not match expected value(s): %s",
                                this.myOAuth2ResourceServerProperties.getAllowedAudienceValues());
                        errors.add(new OAuth2Error(errorCode, errorMessage, errorURI));
                    }

                    final Instant now = Instant.now();
                    final Duration maxClockSkew = this.myOAuth2ResourceServerProperties.getMaxClockSkew();

                    Instant issuedAt = token.getIssuedAt();
                    if (issuedAt == null || issuedAt.isAfter(now.plus(maxClockSkew))) {
                        String errorMessage = String.format(
                                "issued at (iat) claim value missing or after current time plus/minus %s (iat: %s)",
                                maxClockSkew, issuedAt);
                        errors.add(new OAuth2Error(errorCode, errorMessage, errorURI));
                    }

                    if (!errors.isEmpty()) {
                        return OAuth2TokenValidatorResult.failure(errors);
                    }
                    return OAuth2TokenValidatorResult.success();
                })
        );
        return validator;
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        final String resourceServerIssuerURI = this.oAuth2ResourceServerProperties.getJwt().getIssuerUri();
        NimbusJwtDecoder jwtDecoder = (NimbusJwtDecoder) JwtDecoders.fromIssuerLocation(resourceServerIssuerURI);
        jwtDecoder.setJwtValidator(jwtValidator());
        return jwtDecoder;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // Default:
        //http.authorizeRequests().anyRequest().authenticated().and().oauth2Login()
        //        .and().oauth2Client();
        http
                .antMatcher("/**")
                .authorizeRequests(authorizeRequests ->
                        authorizeRequests
                                .antMatchers("/", "/login**", "/webjars/**", "/error**")
                                    .permitAll()
                                .anyRequest()
                                    .authenticated()
                )
                .oauth2Login(withDefaults())
                .oauth2Client(withDefaults())
                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
                .logout(logout -> logout
                        .logoutSuccessHandler(oidcLogoutSuccessHandler())
                )
                .csrf(csrf ->
                        csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                );
    }

    private LogoutSuccessHandler oidcLogoutSuccessHandler() {
        OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler =
                new OidcClientInitiatedLogoutSuccessHandler(this.clientRegistrationRepository);

        // Sets the location that the End-User's User Agent will be redirected to
        // after the logout has been performed at the Provider
        oidcLogoutSuccessHandler.setPostLogoutRedirectUri(URI.create("http://localhost:8080/"));

        return oidcLogoutSuccessHandler;
    }
}
