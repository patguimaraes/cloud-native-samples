package sample.authservice.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import sample.authservice.properties.TestProperties;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
public class ApiControllerTests {

    /** The logger. */
    private static final Logger log = LoggerFactory.getLogger(ApiControllerTests.class);

    private static final String AUTHENTICATION_ERROR = "Full authentication is required to access this resource";

    private static final String BAD_CREDENTIALS_ERROR = "Bad credentials";

    private static final String CHECK_TOKEN_PATH = "/oauth/check_token";

    private static final String KEY = "secret";

    private static final String MISSING_GRANT_TYPE_ERROR = "Missing grant type";

    private static final String MISSING_USERNAME_ERROR = "Required String parameter";

    private static final String TOKEN_KEY_PATH = "/oauth/token_key";

    private static final String TOKEN_PATH = "/oauth/token";

    private static final String TOKEN_CLIENT = "acme-token";

    private static final String UNSUPPORTED_GRANT_TYPE_ERROR = "Unsupported grant type";

    private static final String WEB_CLIENT = "acme-web";

    @Autowired
    @Qualifier("defaultAuthorizationServerTokenServices")
    private DefaultTokenServices tokenServices;

    @Autowired
    private TestProperties testProperties;

    @Autowired
    private MockMvc mvc;

    private String username;
    private String password;

    private ObjectMapper objectMapper;

    @Before
    public void setUp() {
        assertThat(testProperties).as("Object testProperties is null.").isNotNull();

        this.username = testProperties.getUserUsername();
        log.debug("username = " + this.username);

        this.password = testProperties.getUserPassword();
        log.debug("password = PROTECTED");

        this.objectMapper = new ObjectMapper();
    }

    @Test
    public void verifyTokenStoreIsJwt() {
        // @formatter:off
        Object tokenStore = ReflectionTestUtils.getField(tokenServices, "tokenStore");
        log.debug("tokenStore = " + tokenStore);
        assertThat(tokenStore instanceof JwtTokenStore)
                .as("Wrong token store type: " + tokenStore)
                .isTrue();
        // @formatter:on
    }

    @Test
    public void testGetTokenKeyWithNoCredentials() throws Exception {
        // @formatter:off
        String url = TOKEN_KEY_PATH;
        log.debug("url = " + url);
        this.mvc.perform(get(url))
                .andExpect(unauthenticated())
                .andExpect(status().isUnauthorized())
                .andExpect(status().reason(AUTHENTICATION_ERROR))
                .andDo(print());
        // @formatter:on
    }

    @Test
    public void testGetTokenKeyWithInvalidClientCredentials() throws Exception {
        // @formatter:off
        String url = TOKEN_KEY_PATH;
        log.debug("url = " + url);
        this.mvc.perform(get(url).with(httpBasic("dummyClient", "")))
                .andExpect(unauthenticated())
                .andExpect(status().isUnauthorized())
                .andExpect(status().reason(BAD_CREDENTIALS_ERROR))
                .andDo(print());
        // @formatter:on
    }

    @Test
    public void testGetTokenKeyWithValidClientCredentials() throws Exception {
        // @formatter:off
        String url = TOKEN_KEY_PATH;
        log.debug("url = " + url);
        this.mvc.perform(get(url).with(httpBasic(TOKEN_CLIENT, "")))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("\"value\":\"" + KEY + "\"")))
                .andDo(print());
        // @formatter:on
    }

    @Test
    public void testGetCheckTokenWithNoCredentials() throws Exception {
        // @formatter:off
        String url = CHECK_TOKEN_PATH;
        log.debug("url = " + url);
        this.mvc.perform(get(url))
                .andExpect(unauthenticated())
                .andExpect(status().isUnauthorized())
                .andExpect(status().reason(AUTHENTICATION_ERROR))
                .andDo(print());
        // @formatter:on
    }

    @Test
    public void testGetTokenWithNoCredentials() throws Exception {
        // @formatter:off
        String url = TOKEN_PATH;
        log.debug("url = " + url);
        this.mvc.perform(get(url))
                .andExpect(unauthenticated())
                .andExpect(status().isUnauthorized())
                .andExpect(status().reason(AUTHENTICATION_ERROR))
                .andDo(print());
        // @formatter:on
    }

    @Test
    public void testGetTokenWithInvalidClientCredentials() throws Exception {
        // @formatter:off
        String url = TOKEN_PATH;
        log.debug("url = " + url);
        this.mvc.perform(get(url).with(httpBasic(TOKEN_CLIENT, "dummyPassword")))
                .andExpect(unauthenticated())
                .andExpect(status().isUnauthorized())
                .andExpect(status().reason(BAD_CREDENTIALS_ERROR))
                .andDo(print());
        // @formatter:on
    }

    @Test
    public void testGetTokenWithValidClientCredentials() throws Exception {
        // @formatter:off
        String url = TOKEN_PATH;
        log.debug("url = " + url);
        this.mvc.perform(get(url).with(httpBasic(TOKEN_CLIENT, "")))
                .andExpect(status().isMethodNotAllowed())
                .andDo(print());
        // @formatter:on
    }

    @Test
    public void testPostTokenWithValidClientCredentialsAndNoGrantType() throws Exception {
        // @formatter:off
        String url = TOKEN_PATH;
        log.debug("url = " + url);
        this.mvc.perform(post(url).with(httpBasic(TOKEN_CLIENT, "")))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(containsString(MISSING_GRANT_TYPE_ERROR)))
                .andDo(print());
        // @formatter:on
    }

    @Test
    public void testPostTokenWithValidClientCredentialsAndInvalidGrantType() throws Exception {
        // @formatter:off
        String url = TOKEN_PATH;
        log.debug("url = " + url);
        this.mvc.perform(post(url).with(httpBasic(TOKEN_CLIENT, ""))
                                  .param("grant_type", "dummyGrantType"))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(containsString(UNSUPPORTED_GRANT_TYPE_ERROR)))
                .andDo(print());
        // @formatter:on
    }

    @Test
    public void testPostTokenWithValidClientCredentialsAndValidGrantTypeAndNoUsername() throws Exception {
        // @formatter:off
        String url = TOKEN_PATH;
        log.debug("url = " + url);
        this.mvc.perform(post(url).with(httpBasic(TOKEN_CLIENT, ""))
                                  .param("grant_type", "password"))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(containsString(MISSING_USERNAME_ERROR)))
                .andDo(print());
        // @formatter:on
    }

    @Test
    public void testPostTokenWithValidClientCredentialsAndValidGrantTypeAndInvalidCredentials() throws Exception {
        // @formatter:off
        String url = TOKEN_PATH;
        log.debug("url = " + url);
        this.mvc.perform(post(url).with(httpBasic(TOKEN_CLIENT, ""))
                                  .param("grant_type", "password")
                                  .param("username", "dummyUser")
                                  .param("password", "dummyPassword"))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(containsString(BAD_CREDENTIALS_ERROR)))
                .andDo(print());
        // @formatter:on
    }

    @Test
    public void testPostTokenWithValidClientCredentialsAndValidGrantTypeAndValidCredentials() throws Exception {
        // @formatter:off
        String oauth2Token = getOauth2PasswordGrantToken();
        Map<String, Object> oauth2TokenMap = (Map<String, Object>) objectMapper.readValue(oauth2Token, Map.class);
        log.debug("oauth2TokenMap = " + oauth2TokenMap);

        String tokenType = (String) oauth2TokenMap.get("token_type");
        log.debug("tokenType = " + tokenType);
        assertThat(tokenType.toLowerCase()).as("Incorrect token type:" + tokenType)
                .isEqualTo(OAuth2AccessToken.BEARER_TYPE.toLowerCase());

        String accessToken = (String) oauth2TokenMap.get("access_token");
        log.debug("accessToken = " + accessToken);
        validateJwtToken(accessToken);
        // @formatter:on
    }

    private String getOauth2PasswordGrantToken() throws Exception {
        // @formatter:off
        MvcResult mvcResult = this.mvc.perform(post(TOKEN_PATH).with(httpBasic(TOKEN_CLIENT, ""))
                                                               .param("grant_type", "password")
                                                               .param("username", this.username)
                                                               .param("password", this.password))
                                      .andExpect(status().isOk())
                                      .andDo(print())
                                      .andReturn();
        String oauth2Token = mvcResult.getResponse().getContentAsString();
        log.debug("oauth2Token = " + oauth2Token);
        return oauth2Token;
        // @formatter:on
    }

    private void validateJwtToken(String token) throws Exception {
        Jwt jwtToken = JwtHelper.decode(token);
        log.debug("jwtToken = " + jwtToken);
        Map<String, Object> jwtTokenMap = (Map<String, Object>) objectMapper.readValue(jwtToken.getClaims(), Map.class);
        String username = (String) jwtTokenMap.get("user_name");
        log.debug("username = " + username);
        assertThat(username).as("Invalid username: " + username).isEqualTo(this.username);
        log.debug("jwtTokenMap = " + jwtTokenMap);
        String clientId = (String) jwtTokenMap.get("client_id");
        log.debug("clientId = " + clientId);
        assertThat(clientId).as("Invalid client id: " + clientId).isEqualTo(TOKEN_CLIENT);
    }

}
