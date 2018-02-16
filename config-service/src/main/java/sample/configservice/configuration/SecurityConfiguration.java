package sample.configservice.configuration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.boot.actuate.autoconfigure.ManagementServerProperties;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

import sample.common.authentication.CustomAuthenticationManager;

@EnableWebSecurity
public class SecurityConfiguration {

    @Configuration
    @Order(SecurityProperties.ACCESS_OVERRIDE_ORDER)
    public static class FormLoginWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

        /** The logger. */
        private static final Logger log = LoggerFactory.getLogger(SecurityConfiguration.class);

        @Bean
        public AuthenticationManager customAuthenticationManager() {
            AuthenticationManager authenticationManager = new CustomAuthenticationManager();
            log.debug("authenticationManager = " + authenticationManager);
            return authenticationManager;
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            // @formatter:off
            http
                .authorizeRequests()
                    .anyRequest().authenticated()
                    .and()
                .httpBasic()
                    .and()
                .headers()    // add headers
                   .httpStrictTransportSecurity() // add the HTTP Strict Transport Security (HSTS) header
                       .maxAgeInSeconds(31536000)
                       .includeSubDomains(true)
                       .and()  // return the HeadersConfigurer
                   .frameOptions()  // add the HTTP X-Frame-Options header
                       .deny()
                   .cacheControl(); // add cache control headers
            // @formatter:on
        }
    }

    @Configuration
    @Order(ManagementServerProperties.ACCESS_OVERRIDE_ORDER)
    public static class BasicAuthenticationWebSecurityConfigurationAdapter extends WebSecurityConfigurerAdapter {

        protected void configure(HttpSecurity http) throws Exception {
            // @formatter:off
            http
                .authorizeRequests()
                    .antMatchers("/admin/health")
                        .permitAll()
                    .anyRequest()
                        .hasRole("ADMIN")
                    .and()
                .httpBasic()
                    .and()
                .csrf()
                    .disable();
            // @formatter:on
        }
    }

}
