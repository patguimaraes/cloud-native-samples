package sample.common.authentication;

import java.util.ArrayList;
import java.util.Collection;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

public class CustomAuthenticationManager implements AuthenticationManager, AuthenticationProvider {

    /** The logger. */
    private static final Logger log = LoggerFactory.getLogger(CustomAuthenticationManager.class);

    private static final String USERNAME_MISSING_MESSAGE = "Required String parameter 'username' is not present";
    private static final String PASSWORD_MISSING_MESSAGE = "Required String parameter 'password' is not present";

    @Autowired
    MessageSource messageSource;

    private MessageSourceAccessor springSecurityMessages = SpringSecurityMessageSource.getAccessor();

    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        log.debug("authentication = " + authentication);

        String username = (String) authentication.getPrincipal();
        log.debug("username = " + username);
        if ((username == null) || (username.trim().equals(""))) {
            throw new BadCredentialsException(USERNAME_MISSING_MESSAGE);
        }

        String password = (String) authentication.getCredentials();
        log.debug("password = PROTECTED");
        if ((password == null) || (password.trim().equals(""))) {
            throw new BadCredentialsException(PASSWORD_MISSING_MESSAGE);
        }

        Object authenticationDetails = authentication.getDetails();
        log.debug("authenticationDetails = " + authenticationDetails);

        if (username.equals(password)) {
            Collection<GrantedAuthority> grantedAuthorities = new ArrayList<GrantedAuthority>();
            grantedAuthorities.add(new SimpleGrantedAuthority("ROLE_USER"));
            if (username.toLowerCase().contains("admin")) {
                grantedAuthorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
            }
            UsernamePasswordAuthenticationToken newAuthentication = new UsernamePasswordAuthenticationToken(username,
                    password, grantedAuthorities);
            newAuthentication.setDetails(authenticationDetails);
            log.debug("newAuthentication = " + newAuthentication);

            return newAuthentication;
        } else {
            throw new BadCredentialsException(
                    springSecurityMessages.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials"));
        }
    }

    public boolean supports(Class<?> authentication) {
        return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
    }

}
