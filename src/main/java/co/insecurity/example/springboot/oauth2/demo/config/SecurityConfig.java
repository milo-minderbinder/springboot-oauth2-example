package co.insecurity.example.springboot.oauth2.demo.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // Default:
        //http.authorizeRequests().anyRequest().authenticated().and().oauth2Login()
        //        .and().oauth2Client();
        http
                .antMatcher("/**")
                .authorizeRequests()
                    .antMatchers("/", "/login**", "/webjars/**", "/error**")
                    .permitAll()
                .anyRequest()
                    .authenticated()
                .and().oauth2Login()
                .and().logout().logoutSuccessUrl("/").permitAll()
                .and().oauth2Client()
                .and().csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
    }
}
