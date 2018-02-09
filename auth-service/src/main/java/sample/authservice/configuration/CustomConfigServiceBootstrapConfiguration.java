package sample.authservice.configuration;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.http.client.HttpClient;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.HttpClientBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.embedded.Ssl;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.cloud.config.client.ConfigClientProperties;
import org.springframework.cloud.config.client.ConfigServicePropertySourceLocator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.util.Base64Utils;
import org.springframework.web.client.RestTemplate;

@Configuration
public class CustomConfigServiceBootstrapConfiguration {

    /** The logger. */
    private static final Logger log = LoggerFactory.getLogger(CustomConfigServiceBootstrapConfiguration.class);

    public static final String DEFAULT_SSL_PROTOCOL = "TLSv1.2";
    
    @Bean
    public ConfigServicePropertySourceLocator configServicePropertySourceLocator(ConfigClientProperties properties)
            throws KeyManagementException, NoSuchAlgorithmException {
        ConfigServicePropertySourceLocator configServicePropertySourceLocator =  new ConfigServicePropertySourceLocator(properties);
        configServicePropertySourceLocator.setRestTemplate(getSecureRestTemplate(properties));
        log.debug("configured instance of ConfigServicePropertySourceLocator to use custom RestTemplate");
        return configServicePropertySourceLocator;
    }

    private RestTemplate getSecureRestTemplate(ConfigClientProperties client)
            throws KeyManagementException, NoSuchAlgorithmException {
        /*
         * Create a hostname verifier that ignores SSL hostname errors
         */
        HostnameVerifier hostnameVerifier = new HostnameVerifier() {

            public boolean verify(String hostname, javax.net.ssl.SSLSession sslSession) {
                return true;
            }
        };
        log.debug("created custom instance of HostnameVerifier that ignores SSL hostname errors");

        /*
         * Create a trust manager that ignores SSL certificate errors
         */
        TrustManager trustManager = new X509TrustManager() {

            @Override
            public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType)
                    throws java.security.cert.CertificateException {
            }

            @Override
            public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType)
                    throws java.security.cert.CertificateException {
            }

            @Override
            public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                return null;
            }
        };
        log.debug("created custom instance of TrustManager that ignores SSL certificate errors");

        /*
         * Create the SSL context
         */
        log.debug("DEFAULT_SSL_PROTOCOL = " + DEFAULT_SSL_PROTOCOL);
        SSLContext sslContext = SSLContext.getInstance(DEFAULT_SSL_PROTOCOL);
        log.debug("created custom sslContext");

        /*
         * Configure the SSL context to ignore certificate errors
         */
        sslContext.init(null, new TrustManager[] { trustManager }, null);
        log.debug("initialized the custom sslContext with the custom TrustManager");

        /*
         * Get the SSL Socket Factory from the SSL context
         */
        SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
        log.debug("obtained sslSocketFactory initialized with custom TrustManager");

        /*
         * Create a ClientHttpRequestFactory that ignores SSL hostname errors and certificate errors
         */
        SSLConnectionSocketFactory sslConnectionSocketFactory = new SSLConnectionSocketFactory(
                sslSocketFactory, hostnameVerifier);
        HttpClientBuilder httpClientBuilder = HttpClientBuilder.create();
        httpClientBuilder.setSSLSocketFactory(sslConnectionSocketFactory);
        HttpClient httpClient = httpClientBuilder.build();
        ClientHttpRequestFactory clientHttpRequestFactory = new HttpComponentsClientHttpRequestFactory(httpClient);
        log.debug("created custom ClientHttpRequestFactory that ignores SSL hostname and certificate errors");

        /*
         * Create a custom RestTemplate that ignores SSL hostname and certificate errors
         */
        RestTemplate restTemplate = new RestTemplate(clientHttpRequestFactory);
        log.debug("created custom RestTemplate that ignores SSL hostname and certificate errors");

        /*
         * Configure the custom RestTemplate to use Basic Authentication
         */
        String username = client.getUsername();
        log.debug("username = " + username);
        String password = client.getPassword();
        log.debug("password = PROTECTED");
        Map<String, String> headers = new HashMap<>(client.getHeaders());

        if ((username == null) || (password == null)) {
            throw new IllegalStateException(
                    "You must set both the 'username' and the 'password'");
        }

        byte[] token = Base64Utils.encode((username + ":" + password).getBytes());
        headers.put("Authorization", "Basic " + new String(token));
        restTemplate.setInterceptors(Arrays.<ClientHttpRequestInterceptor> asList(
                    new GenericRequestHeaderInterceptor(headers)));
        log.debug("configured custom RestTemplate to use Basic Authentication");
 
        return restTemplate;
    }

    public static class GenericRequestHeaderInterceptor implements ClientHttpRequestInterceptor {

        private final Map<String, String> headers;

        public GenericRequestHeaderInterceptor(Map<String, String> headers) {
            this.headers = headers;
        }

        @Override
        public ClientHttpResponse intercept(HttpRequest request, byte[] body,
                ClientHttpRequestExecution execution) throws IOException {
            for (Entry<String, String> header : headers.entrySet()) {
                request.getHeaders().add(header.getKey(), header.getValue());
            }
            return execution.execute(request, body);
        }

    }

}
