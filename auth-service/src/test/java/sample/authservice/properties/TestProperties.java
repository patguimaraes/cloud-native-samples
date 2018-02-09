package sample.authservice.properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "test", ignoreUnknownFields = false)
public class TestProperties {

    /** The logger. */
    private static final Logger log = LoggerFactory.getLogger(TestProperties.class);

    public String getUserUsername() {
        return userUsername;
    }

    public void setUserUsername(String userUsername) {
        this.userUsername = userUsername;
    }

    public String getUserPassword() {
        return userPassword;
    }

    public void setUserPassword(String userPassword) {
        this.userPassword = userPassword;
    }

    public String getAdminUsername() {
        return adminUsername;
    }

    public void setAdminUsername(String adminUsername) {
        this.adminUsername = adminUsername;
    }

    public String getAdminPassword() {
        return adminPassword;
    }

    public void setAdminPassword(String adminPassword) {
        this.adminPassword = adminPassword;
    }

    private String userUsername;
    private String userPassword;
    private String adminUsername;
    private String adminPassword;

    public TestProperties() {
        log.debug("Creating instance of class TestProperties");
    }

}
