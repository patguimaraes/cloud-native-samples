package sample.authservice.web;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class ApplicationController {

    /** The logger. */
    private static final Logger log = LoggerFactory.getLogger(ApplicationController.class);

    private static final String HOME_URL = "/home";

    @GetMapping(value = "/")
    public String root() {
        String homeUrl = HOME_URL;
        log.debug("homeUrl = " + homeUrl);
        String viewName = "redirect:" + homeUrl;
        log.debug("returning view " + viewName);
        return viewName;
    }

    @GetMapping(value = "/home")
    public String home() {
        String viewName = "home";
        log.debug("returning view " + viewName);
        return viewName;
    }

    @GetMapping(value = "/login")
    public String login() {
        String viewName = "login";
        log.debug("returning view " + viewName);
        return viewName;
    }

    @GetMapping(value = "/hello")
    public String hello() {
        String viewName = "hello";
        log.debug("returning view " + viewName);
        return viewName;
    }

}
