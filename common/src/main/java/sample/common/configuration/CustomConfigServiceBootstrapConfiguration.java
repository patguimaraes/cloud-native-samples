package sample.common.configuration;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.cloud.config.client.ConfigClientProperties;
import org.springframework.cloud.config.client.ConfigServicePropertySourceLocator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

@Configuration
public class CustomConfigServiceBootstrapConfiguration {

    /** The logger. */
    private static final Logger log = LoggerFactory.getLogger(CustomConfigServiceBootstrapConfiguration.class);

    public CustomConfigServiceBootstrapConfiguration() {
        log.debug("Creating instance of class CustomConfigServiceBootstrapConfiguration");
    }

    @Bean
    public ConfigServicePropertySourceLocator configServicePropertySourceLocator(ConfigClientProperties properties,
            RestTemplate restTemplate) throws KeyManagementException, NoSuchAlgorithmException {
        ConfigServicePropertySourceLocator configServicePropertySourceLocator = new ConfigServicePropertySourceLocator(
                properties);
        configServicePropertySourceLocator.setRestTemplate(restTemplate);
        log.debug(
                "configured instance of ConfigServicePropertySourceLocator to use RestTemplate with custom SSL configuration");
        return configServicePropertySourceLocator;
    }

}
