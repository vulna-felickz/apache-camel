package com.example.routes;

import org.apache.camel.Exchange;
import org.apache.camel.Message;
import org.apache.camel.builder.RouteBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * XSS and Log Injection vulnerabilities via Camel message body and headers.
 *
 * Demonstrates:
 *   - Exchange#getMessage()
 *   - Message#getBody(Class)
 *   - Message#getHeader(String, Class)
 *   - Message#getHeader(String)
 *   - Message#setBody(Object)
 *   - Message#setHeader(String, Object)
 */
@Component
public class XssAndLogInjectionRoute extends RouteBuilder {

    private static final Logger log = LoggerFactory.getLogger(XssAndLogInjectionRoute.class);

    @Override
    public void configure() throws Exception {
        // Route 1: XSS - GET /api/greet?name=...
        from("servlet:/greet?httpMethodRestrict=GET")
            .routeId("xss-reflected")
            .process(exchange -> {
                Message message = exchange.getMessage();
                // VULN: user input from header rendered directly as HTML
                String name = message.getHeader("name", String.class);
                String html = "<html><body><h1>Hello, " + name + "!</h1></body></html>";
                message.setBody(html);
                // VULN: Content-Type header set to text/html — browser will render scripts
                message.setHeader("Content-Type", "text/html");
            });

        // Route 2: Log Injection - GET /api/status with X-User header
        from("servlet:/status?httpMethodRestrict=GET")
            .routeId("log-injection")
            .process(exchange -> {
                Message message = exchange.getMessage();
                // VULN: user-controlled header value written to log unsanitized
                String username = message.getHeader("X-User", String.class);
                String requestId = message.getHeader("X-Request-Id", String.class);
                log.info("Processing request for user: " + username + " requestId: " + requestId);
                message.setBody("OK");
            });

        // Route 3: Header injection / response splitting - GET /api/redirect?location=...
        from("servlet:/redirect?httpMethodRestrict=GET")
            .routeId("header-injection")
            .process(exchange -> {
                Message message = exchange.getMessage();
                // VULN: user input placed into Location header without sanitization
                String location = message.getHeader("location", String.class);
                message.setHeader("Location", location);
                message.setHeader(Exchange.HTTP_RESPONSE_CODE, 302);
                message.setBody("");
            });

        // Route 4: XSS via POST body - POST /api/comment
        from("servlet:/comment?httpMethodRestrict=POST")
            .routeId("xss-stored-body")
            .process(exchange -> {
                Message message = exchange.getMessage();
                // VULN: POST body (user content) returned directly in HTML response
                String comment = message.getBody(String.class);
                String html = "<html><body><div class='comment'>" + comment + "</div></body></html>";
                message.setBody(html);
                message.setHeader("Content-Type", "text/html");
            });
    }
}
