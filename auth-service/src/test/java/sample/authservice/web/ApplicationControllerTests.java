package sample.authservice.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.CoreMatchers.endsWith;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.logout;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
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
public class ApplicationControllerTests {

    /** The logger. */
    private static final Logger log = LoggerFactory.getLogger(ApplicationControllerTests.class);

    private static final String COULD_NOT_VERIFY_CSRF_TOKEN_ERROR_MESSAGE_SUBSTRING = "Could not verify the provided CSRF token";

    private static final String INVALID_CSRF_ERROR_MESSAGE_SUBSTRING = "Invalid CSRF Token";

    private static final String LOGIN_URL = "/login";

    private static final String LOGIN_URL_CONTENT_SUBSTRING = "Password:";

    private static final String LOGIN_URL_WITH_ERROR = "/login?error";

    private static final String PUBLIC_HOME_URL = "/home";

    private static final String PUBLIC_HOME_URL_CONTENT_SUBSTRING = "Welcome";

    private static final String SECURE_HOME_URL = "/hello";

    private static final String ROOT_URL = "/";

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
    public void testRedirectionToHomeAndHeaders() throws Exception {
        // @formatter:off
        String url = ROOT_URL;
        log.debug("url = " + url);
        this.mvc.perform(get("/"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", PUBLIC_HOME_URL))
                .andExpect(unauthenticated())
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andDo(print());
        // @formatter:on
    }

    @Test
    public void testGetPublicHome() throws Exception {
        // @formatter:off
        String url = PUBLIC_HOME_URL;
        log.debug("url = " + url);
        this.mvc.perform(get(url))
                .andExpect(unauthenticated())
                .andExpect(status().isOk())
                .andExpect(content().string(containsString(PUBLIC_HOME_URL_CONTENT_SUBSTRING)))
                .andDo(print());
        // @formatter:on
    }

    @Test
    public void testGetSecureHome() throws Exception {
        // @formatter:off
        String url = SECURE_HOME_URL;
        log.debug("url = " + url);
        this.mvc.perform(get(url))
                .andExpect(unauthenticated())
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", endsWith(LOGIN_URL)))
                .andDo(print());
        // @formatter:on
    }

    @Test
    public void testGetLogin() throws Exception {
        // @formatter:off
        String url = LOGIN_URL;
        log.debug("url = " + url);
        this.mvc.perform(get(url))
                .andExpect(unauthenticated())
                .andExpect(status().isOk())
                .andExpect(content().string(containsString(LOGIN_URL_CONTENT_SUBSTRING)))
                .andDo(print());
        // @formatter:on
    }

    @Test
    public void testPostLoginWithNoCredentialsAndNoCsrf() throws Exception {
        // @formatter:off
        String url = LOGIN_URL;
        log.debug("url = " + url);
        this.mvc.perform(post(url))
                .andExpect(unauthenticated())
                .andExpect(status().isForbidden())
                .andExpect(status().reason(containsString(COULD_NOT_VERIFY_CSRF_TOKEN_ERROR_MESSAGE_SUBSTRING)))
                .andDo(print());
        // @formatter:on
    }

    @Test
    public void testPostLoginWithNoCredentialsAndInvalidCsrf() throws Exception {
        // @formatter:off
        String url = LOGIN_URL;
        log.debug("url = " + url);
        this.mvc.perform(post(url).with(csrf().useInvalidToken()))
                .andExpect(unauthenticated())
                .andExpect(status().isForbidden())
                .andExpect(status().reason(containsString(INVALID_CSRF_ERROR_MESSAGE_SUBSTRING)))
                .andDo(print());
        // @formatter:on
    }

    @Test
    public void testPostLoginWithNoCredentialsAndValidCsrf() throws Exception {
        // @formatter:off
        String url = LOGIN_URL;
        log.debug("url = " + url);
        this.mvc.perform(post(url).with(csrf()))
                .andExpect(unauthenticated())
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", LOGIN_URL_WITH_ERROR))
                .andDo(print());
        // @formatter:on
    }

    @Test
    public void testPostLoginWithInvalidCredentialsAndValidCsrf() throws Exception {
        // @formatter:off
        String url = LOGIN_URL;
        log.debug("url = " + url);
        this.mvc.perform(post(url).param("username", "dummyUser").param("password", "dummyPassword").with(csrf()))
                .andExpect(unauthenticated())
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", LOGIN_URL_WITH_ERROR))
                .andDo(print());
        // @formatter:on
    }

    @Test
    public void testPostLoginWithValidCredentialsAndValidCsrf() throws Exception {
        // @formatter:off
        String url = LOGIN_URL;
        log.debug("url = " + url);
        this.mvc.perform(post(url).param("username", this.userUsername).param("password", this.userPassword).with(csrf()))
                .andExpect(authenticated())
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", SECURE_HOME_URL))
                .andDo(print());
        // @formatter:on
    }

    /*
     * The formLogin method automatically adds user "user" and password
     * "password" if no user and password are specified, and also automatically
     * adds a valid CSRF token
     */
    @Test
    public void testFormLoginWithInvalidCredentials() throws Exception {
        // @formatter:off
        String url = LOGIN_URL;
        log.debug("url = " + url);
        this.mvc.perform(formLogin(url).user("dummyUser").password("dummyPassword"))
                .andExpect(unauthenticated())
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", LOGIN_URL_WITH_ERROR))
                .andDo(print());
        // @formatter:on
    }

    @Test
    public void testFormLoginWithValidCredentials() throws Exception {
        // @formatter:off
        String url = LOGIN_URL;
        log.debug("url = " + url);
        this.mvc.perform(formLogin(url).user(this.userUsername).password(this.userPassword))
                .andExpect(authenticated())
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", SECURE_HOME_URL))
                .andDo(print());
        // @formatter:on
    }

    @Test
    public void testLogout() throws Exception {
        // @formatter:off
        /*
         * Perform a login
         */
        String url = LOGIN_URL;
        log.debug("url = " + url);
        this.mvc.perform(formLogin(url).user(this.userUsername).password(this.userPassword))
                .andExpect(authenticated())
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", SECURE_HOME_URL))
                .andDo(print());

        /*
         * Perform a logout
         */
        this.mvc.perform(logout())
                .andExpect(unauthenticated())
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", PUBLIC_HOME_URL))
                .andDo(print());
        // @formatter:on
    }

}
