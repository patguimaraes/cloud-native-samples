package sample.common.configuration;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.cloud.config.client.ConfigClientProperties;
import org.springframework.cloud.config.client.ConfigServicePropertySourceLocator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.util.Base64Utils;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.util.Map.Entry;

@Configuration
public class CustomConfigServiceBootstrapConfiguration {

    /** The logger. */
    private static final Logger log = LoggerFactory.getLogger(CustomConfigServiceBootstrapConfiguration.class);

    public CustomConfigServiceBootstrapConfiguration() {
        log.debug("Creating instance of class CustomConfigServiceBootstrapConfiguration");
    }

    @Bean
    public ConfigServicePropertySourceLocator configServicePropertySourceLocator(ConfigClientProperties properties,
            ClientHttpRequestFactory clientHttpRequestFactory) throws KeyManagementException, NoSuchAlgorithmException {
        /*
         * The injected ClientHttpRequestFactory has been configured to ignore SSL certificate errors
         * 
         * Create a custom RestTemplate with the injected ClientHttpRequestFactory
         */
        RestTemplate restTemplate = new RestTemplate(clientHttpRequestFactory);
        log.debug("created custom RestTemplate that ignores SSL hostname and certificate errors");

        /*
         * Configure the custom RestTemplate to use Basic Authentication with the appropriate credentials to access the Config Server
         */
        String username = properties.getUsername();
        log.debug("username = " + username);
        String password = properties.getPassword();
        log.debug("password = PROTECTED");
        Map<String, String> headers = new HashMap<>(properties.getHeaders());

        if ((username == null) || (password == null)) {
            throw new IllegalStateException("You must set both the 'username' and the 'password'");
        }

        byte[] token = Base64Utils.encode((username + ":" + password).getBytes());
        headers.put("Authorization", "Basic " + new String(token));
        restTemplate.setInterceptors(
                Arrays.<ClientHttpRequestInterceptor>asList(new GenericRequestHeaderInterceptor(headers)));
        log.debug("configured custom RestTemplate to use Basic Authentication");

        /*
         * Configure the custom ConfigServicePropertySourceLocator to use the custom RestTemplate
         */
        ConfigServicePropertySourceLocator configServicePropertySourceLocator = new ConfigServicePropertySourceLocator(
                properties);
        configServicePropertySourceLocator.setRestTemplate(restTemplate);
        log.debug(
                "configured instance of ConfigServicePropertySourceLocator to use RestTemplate with custom SSL configuration");
        return configServicePropertySourceLocator;
    }
    
    public static class GenericRequestHeaderInterceptor implements ClientHttpRequestInterceptor {

        private final Map<String, String> headers;

        public GenericRequestHeaderInterceptor(Map<String, String> headers) {
            this.headers = headers;
        }

        @Override
        public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution)
                throws IOException {
            for (Entry<String, String> header : headers.entrySet()) {
                request.getHeaders().add(header.getKey(), header.getValue());
            }
            return execution.execute(request, body);
        }

    }

}
