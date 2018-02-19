package sample.userservice.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.net.URI;

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
import org.springframework.web.util.UriTemplate;

import sample.userservice.properties.TestProperties;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
public class ApiControllerTests {

    /** The logger. */
    private static final Logger log = LoggerFactory.getLogger(ApiControllerTests.class);

    private static final String USER_PATH = "/users/{username}";

    @Autowired
    private TestProperties testProperties;

    @Autowired
    private MockMvc mvc;

    private String username;
    private String password;
    private String adminUsername;
    private String adminPassword;

    @Before
    public void setUp() {
        assertThat(testProperties).as("Object testProperties is null.").isNotNull();

        this.username = testProperties.getUserUsername();
        log.debug("username = " + this.username);

        this.password = testProperties.getUserPassword();
        log.debug("password = PROTECTED");

        this.adminUsername = testProperties.getAdminUsername();
        log.debug("adminUsername = " + adminUsername);

        this.adminPassword = testProperties.getAdminPassword();
        log.debug("adminPassword = PROTECTED");
    }

    @Test
    public void getUserWithNoCredentials() throws Exception {
        // @formatter:off
        URI uri = (new UriTemplate(USER_PATH).expand(this.username));
        String url = uri.toString();
        log.info("url = " + url);
        this.mvc.perform(get(url))
                .andExpect(status().isUnauthorized())
                .andExpect(unauthenticated())
                .andDo(print());
        // @formatter:on
    }

    @Test
    public void getUserWithInvalidCredentials() throws Exception {
        // @formatter:off
        URI uri = (new UriTemplate(USER_PATH).expand(this.username));
        String url = uri.toString();
        log.info("url = " + url);
        this.mvc.perform(get(url).with(httpBasic("dummy", "dummy")))
                .andExpect(status().isUnauthorized())
                .andExpect(unauthenticated())
                .andDo(print());
        // @formatter:on
    }

    @Test
    public void getUserWithValidCredentials() throws Exception {
        // @formatter:off
        URI uri = (new UriTemplate(USER_PATH).expand(this.username));
        String url = uri.toString();
        log.info("url = " + url);
        this.mvc.perform(get(url).with(httpBasic(this.username, this.password)))
                .andExpect(status().isOk())
                .andExpect(authenticated().withRoles("USER"))
                .andDo(print());
        // @formatter:on
    }

    @Test
    public void getUserWithValidCredentialsForOtherUser() throws Exception {
        // @formatter:off
        URI uri = (new UriTemplate(USER_PATH).expand(this.adminUsername));
        String url = uri.toString();
        log.info("url = " + url);
        this.mvc.perform(get(url).with(httpBasic(this.username, this.password)))
                .andExpect(status().isForbidden())
                .andExpect(authenticated())
                .andDo(print());
        // @formatter:on
    }

    @Test
    public void getAdminWithValidCredentials() throws Exception {
        // @formatter:off
        URI uri = (new UriTemplate(USER_PATH).expand(this.adminUsername));
        String url = uri.toString();
        log.info("url = " + url);
        this.mvc.perform(get(url).with(httpBasic(this.adminUsername, this.adminPassword)))
                .andExpect(status().isOk())
                .andExpect(authenticated().withRoles("USER","ADMIN"))
                .andDo(print());
        // @formatter:on
    }

}
