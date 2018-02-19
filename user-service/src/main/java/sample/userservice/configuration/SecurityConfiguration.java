package sample.userservice.configuration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.boot.actuate.autoconfigure.ManagementServerProperties;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.InMemoryUserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;

import sample.common.authentication.CustomAuthenticationManager;

@EnableGlobalMethodSecurity(prePostEnabled = true)
@EnableWebSecurity
public class SecurityConfiguration {

    @Configuration
    @Order(SecurityProperties.ACCESS_OVERRIDE_ORDER)
    public static class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

        /** The logger. */
        private static final Logger log = LoggerFactory.getLogger(SecurityConfiguration.class);

        @Bean
        public AuthenticationManager customAuthenticationManager() {
            AuthenticationManager authenticationManager = new CustomAuthenticationManager();
            log.debug("authenticationManager = " + authenticationManager);
            return authenticationManager;
        }

        @Bean
        @Override
        /*
         * Override this method to expose a UserDetailsService created from
         * configure(AuthenticationManagerBuilder) as a bean.
         */
        public UserDetailsService userDetailsServiceBean() throws Exception {
            UserDetailsService userDetailsService = super.userDetailsServiceBean();
            return userDetailsService;
        }

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {

            log.debug("creating in-memory users");

            String userUsername = "user";
            log.debug("userUsername = " + userUsername);
            String userPassword = userUsername;
            log.debug("userPassword = PROTECTED");

            String adminUsername = "admin";
            log.debug("adminUsername = " + adminUsername);
            String adminPassword = adminUsername;
            log.debug("adminPassword = PROTECTED");

            InMemoryUserDetailsManagerConfigurer<AuthenticationManagerBuilder> builder = auth.inMemoryAuthentication();
            builder.withUser(userUsername).password(userPassword).roles("USER");
            builder.withUser(adminUsername).password(adminPassword).roles("USER", "ADMIN");
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            // @formatter:off
            http
                .authorizeRequests()
                    .antMatchers("/admin/health")
                        .permitAll()
                    .antMatchers("/admin/**")
                        .hasRole("ADMIN")
                    .anyRequest().authenticated()
                    .and()
                .httpBasic()
                    .and()
                .csrf()
                    .disable();

            // @formatter:on
        }
    }

    @Configuration
    @Order(ManagementServerProperties.ACCESS_OVERRIDE_ORDER)
    public static class ManagementSecurityConfiguration extends WebSecurityConfigurerAdapter {

        protected void configure(HttpSecurity http) throws Exception {
            // @formatter:off
            http
                .antMatcher("/admin/**")
                .authorizeRequests()
                    .antMatchers("/admin/health")
                        .permitAll()
                    .anyRequest().hasRole("ADMIN")
                    .and()
                .httpBasic()
                    .and()
                .csrf()
                    .disable();
            // @formatter:on
        }
    }

}
