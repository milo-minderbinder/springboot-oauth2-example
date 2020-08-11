package co.insecurity.example.springboot.oauth2.demo.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.Set;

@ConfigurationProperties(prefix = "my.oauth2.resource-server")
public class MyOAuth2ResourceServerProperties {
    private Set<String> allowedAudienceValues = Set.of(
            "api://default"
    );
    private Duration maxClockSkew = Duration.ofSeconds(30);

    public Set<String> getAllowedAudienceValues() {
        return allowedAudienceValues;
    }

    public void setAllowedAudienceValues(Set<String> allowedAudienceValues) {
        this.allowedAudienceValues = allowedAudienceValues;
    }

    public Duration getMaxClockSkew() {
        return maxClockSkew;
    }

    public void setMaxClockSkew(Duration maxClockSkew) {
        this.maxClockSkew = maxClockSkew;
    }
}
