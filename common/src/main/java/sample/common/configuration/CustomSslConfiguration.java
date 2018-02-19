package sample.common.configuration;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.http.client.HttpClient;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.HttpClientBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;

/**
 * This class creates an instance of ClientHttpRequestFactory that ignores SSL certificate errors.
 */
@Configuration
public class CustomSslConfiguration {

    /** The logger. */
    private static final Logger log = LoggerFactory.getLogger(CustomSslConfiguration.class);

    public static final String DEFAULT_SSL_PROTOCOL = "TLSv1.2";

    public CustomSslConfiguration() {
        log.debug("Creating instance of class CustomSslConfiguration");
    }

    @Bean
    public ClientHttpRequestFactory clientHttpRequestFactory()
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
         * Create a ClientHttpRequestFactory that ignores SSL hostname errors
         * and certificate errors
         */
        SSLConnectionSocketFactory sslConnectionSocketFactory = new SSLConnectionSocketFactory(sslSocketFactory,
                hostnameVerifier);
        HttpClientBuilder httpClientBuilder = HttpClientBuilder.create();
        httpClientBuilder.setSSLSocketFactory(sslConnectionSocketFactory);
        HttpClient httpClient = httpClientBuilder.build();
        ClientHttpRequestFactory clientHttpRequestFactory = new HttpComponentsClientHttpRequestFactory(httpClient);
        log.debug("created custom ClientHttpRequestFactory that ignores SSL hostname and certificate errors");
        
        return clientHttpRequestFactory;
    }

}
