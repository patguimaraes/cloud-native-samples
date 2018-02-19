package sample.userservice.web;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ApiController {

    /** The logger. */
    private static final Logger log = LoggerFactory.getLogger(ApiController.class);

    @Autowired
    UserDetailsService userDetailsService;

    @GetMapping(value = "/users/{username:[a-zA-Z0-9\\.\\-_@]+}", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    @PreAuthorize("#username == authentication.name")
    public Map<String, Object> getUser(@PathVariable String username, HttpServletResponse response) throws IOException {
        log.debug("username = " + username);
        try {
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            log.debug("userDetails = " + userDetails);
            Map<String, Object> user = new HashMap<String, Object>();
            boolean isEnabled = userDetails.isEnabled();
            log.debug("userDetails.isEnabled() = " + isEnabled);
            log.debug("userDetails.isCredentialsNonExpired() = " + userDetails.isCredentialsNonExpired());
            log.debug("userDetails.isAccountNonExpired() = " + userDetails.isAccountNonExpired());
            log.debug("userDetails.isAccountNonLocked() = " + userDetails.isAccountNonLocked());
            if (isEnabled) {
                user.put("username", userDetails.getUsername());
                Collection<GrantedAuthority> authorities = (Collection<GrantedAuthority>) userDetails.getAuthorities();
                user.put("authorities", authorities);
                Collection<String> roles = new ArrayList<String>();
                for (GrantedAuthority authority : authorities) {
                    roles.add(authority.getAuthority());
                }
                user.put("roles", roles);
                log.debug("user = " + user);
            }
            return user;
        } catch (UsernameNotFoundException exception) {
            int statusCode = HttpServletResponse.SC_NOT_FOUND;
            String errorMessage = exception.getMessage();
            log.debug("returning status code " + statusCode + " with error message " + errorMessage);
            response.sendError(statusCode, errorMessage);
            return null;
        }
    }

}
