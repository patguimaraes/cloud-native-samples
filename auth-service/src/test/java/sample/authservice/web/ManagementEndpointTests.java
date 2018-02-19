package sample.authservice.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import sample.authservice.properties.TestProperties;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
public class ManagementEndpointTests {

    /** The logger. */
    private static final Logger log = LoggerFactory.getLogger(ManagementEndpointTests.class);

    private static final String ACCESS_DENIED_ERROR_MESSAGE = "Access is denied";

    private static final String ADMIN_HEALTH_ENDPOINT = "/admin/health";

    private static final String ADMIN_HEALTH_ENDPOINT_CONTENT_SUBSTRING = "\"status\":\"UP\"";

    private static final String ADMIN_BEANS_ENDPOINT = "/admin/beans";

    private static final String ADMIN_BEANS_ENDPOINT_CONTENT_SUBSTRING = "\"beans\":[{";

    private static final String ADMIN_REFRESH_ENDPOINT = "/admin/refresh";

    private static final String BAD_CREDENTIALS_ERROR_MESSAGE = "Bad credentials";

    @Autowired
    private TestProperties testProperties;

    @Autowired
    private MockMvc mvc;

    private String userUsername;
    private String userPassword;
    private String adminUsername;
    private String adminPassword;

    @Before
    public void setUp() {
        assertThat(testProperties).as("Object testProperties is null.").isNotNull();

        this.userUsername = testProperties.getUserUsername();
        log.debug("userUsername = " + this.userUsername);
        assertThat(this.userUsername).as("Object userUsername is null.").isNotNull();

        this.userPassword = testProperties.getUserPassword();
        log.debug("userPassword = PROTECTED");
        assertThat(this.userPassword).as("Object userPassword is null.").isNotNull();

        this.adminUsername = testProperties.getAdminUsername();
        log.debug("adminUsername = " + this.adminUsername);
        assertThat(this.adminUsername).as("Object adminUsername is null.").isNotNull();

        this.adminPassword = testProperties.getAdminPassword();
        log.debug("adminPassword = PROTECTED");
        assertThat(this.adminPassword).as("Object adminPassword is null.").isNotNull();
    }

    @Test
    public void testHealthEndpointWithBasicAuthenticationAndNoCredentials() throws Exception {
        // @formatter:off
        String url = ADMIN_HEALTH_ENDPOINT;
        log.debug("url = " + url);
        this.mvc.perform(get(url))
                .andExpect(status().isOk())
                .andExpect(unauthenticated())
                .andExpect(content().string(containsString(ADMIN_HEALTH_ENDPOINT_CONTENT_SUBSTRING)))
                .andDo(print());
        // @formatter:on
    }

    @Test
    public void testAdminEndpointWithBasicAuthenticationAndNoCredentials() throws Exception {
        // @formatter:off
        String url = ADMIN_BEANS_ENDPOINT;
        log.debug("url = " + url);
        this.mvc.perform(get(url))
                .andExpect(unauthenticated())
                .andExpect(status().isUnauthorized())
                .andDo(print());
        // @formatter:on
    }

    @Test
    public void testAdminEndpointWithBasicAuthenticationAndInvalidCredentials() throws Exception {
        // @formatter:off
        String url = ADMIN_BEANS_ENDPOINT;
        log.debug("url = " + url);
        this.mvc.perform(get(url).with(httpBasic("dummyUser", "dummyPassword")))
                .andExpect(unauthenticated())
                .andExpect(status().isUnauthorized())
                .andExpect(status().reason(BAD_CREDENTIALS_ERROR_MESSAGE))
                .andDo(print());
        // @formatter:on
    }

    @Test
    public void testAdminEndpointWithBasicAuthenticationAndNonAdminCredentials() throws Exception {
        // @formatter:off
        String url = ADMIN_BEANS_ENDPOINT;
        log.debug("url = " + url);
        this.mvc.perform(get(url).with(httpBasic(this.userUsername, this.userPassword)))
                .andExpect(authenticated())
                .andExpect(status().isForbidden())
                .andExpect(status().reason(ACCESS_DENIED_ERROR_MESSAGE))
                .andDo(print());
        // @formatter:on
    }

    @Test
    public void testAdminEndpointWithBasicAuthenticationAndAdminCredentials() throws Exception {
        // @formatter:off
        String url = ADMIN_BEANS_ENDPOINT;
        log.debug("url = " + url);
        this.mvc.perform(get(url).with(httpBasic(this.adminUsername, this.adminPassword)))
                .andExpect(authenticated())
                .andExpect(status().isOk())
                .andExpect(content().string(containsString(ADMIN_BEANS_ENDPOINT_CONTENT_SUBSTRING)))
                .andDo(print());
        // @formatter:on
    }

    @Test
    public void testGetRefreshEndpointWithBasicAuthenticationAndAdminCredentials() throws Exception {
        // @formatter:off
        String url = ADMIN_REFRESH_ENDPOINT;
        log.debug("url = " + url);
        this.mvc.perform(get(url).with(httpBasic(this.adminUsername, this.adminPassword)))
                .andExpect(authenticated())
                .andExpect(status().isMethodNotAllowed())
                .andDo(print());
        // @formatter:on
    }

    @Test
    public void testPostRefreshEndpointWithBasicAuthenticationAndAdminCredentials() throws Exception {
        // @formatter:off
        String url = ADMIN_REFRESH_ENDPOINT;
        log.debug("url = " + url);
        this.mvc.perform(post(url).with(httpBasic(this.adminUsername, this.adminPassword)))
                .andExpect(authenticated())
                .andExpect(status().isOk())
                .andDo(print());
        // @formatter:on
    }

}
