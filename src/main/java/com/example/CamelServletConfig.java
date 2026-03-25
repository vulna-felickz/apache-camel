package com.example;

import org.apache.camel.component.servlet.CamelHttpTransportServlet;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Registers the Camel servlet so all routes under /api/* are reachable via HTTP.
 */
@Configuration
public class CamelServletConfig {

    @Bean
    public ServletRegistrationBean<CamelHttpTransportServlet> camelServlet() {
        CamelHttpTransportServlet servlet = new CamelHttpTransportServlet();
        ServletRegistrationBean<CamelHttpTransportServlet> registration =
                new ServletRegistrationBean<>(servlet, "/api/*");
        registration.setName("CamelServlet");
        return registration;
    }
}
