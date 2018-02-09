package sample.authservice.configuration;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() throws IOException {
        String signingKey = "secret";
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        converter.setSigningKey(signingKey);
        return converter;
    }

    @Bean
    public JwtTokenStore jwtTokenStore() throws IOException {
        return new JwtTokenStore(jwtAccessTokenConverter());
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
        // @formatter:off
        oauthServer
                .tokenKeyAccess("hasAuthority('ROLE_TRUSTED_WEB_CLIENT') || hasAuthority('ROLE_TRUSTED_TOKEN_CLIENT')")
                .checkTokenAccess(
                        "hasAuthority('ROLE_TRUSTED_WEB_CLIENT') || hasAuthority('ROLE_TRUSTED_TOKEN_CLIENT')");
        // @formatter:on
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        // @formatter:off
        endpoints
                .authenticationManager(this.authenticationManager)
                .tokenStore(jwtTokenStore())
                .accessTokenConverter(jwtAccessTokenConverter());
        // @formatter:on
    }

    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        // @formatter:off
        clients.inMemory()
            .withClient("acme-web")
                .authorizedGrantTypes("authorization_code")
                .authorities("ROLE_TRUSTED_WEB_CLIENT")
                .scopes("read")      // scopes must be specified
                .accessTokenValiditySeconds(60)
                .autoApprove(true)
        .and()
            .withClient("acme-token")
                .authorizedGrantTypes("password")
                .authorities("ROLE_TRUSTED_TOKEN_CLIENT")
                .scopes("read")      // scopes must be specified
                .accessTokenValiditySeconds(60)
                .autoApprove(true);
        // @formatter:on
    }

}
