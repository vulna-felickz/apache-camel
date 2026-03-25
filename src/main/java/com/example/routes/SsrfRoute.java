package com.example.routes;

import org.apache.camel.Exchange;
import org.apache.camel.Message;
import org.apache.camel.builder.ExchangeBuilder;
import org.apache.camel.builder.RouteBuilder;
import org.springframework.stereotype.Component;

/**
 * Server-Side Request Forgery (SSRF) via Camel HTTP component.
 *
 * Demonstrates:
 *   - Exchange#getMessage()
 *   - Message#getHeader(String)
 *   - Message#getHeader(String, Class)
 *   - Message#setBody(Object)
 *   - ExchangeBuilder#withBody(Object)
 *   - ProducerTemplate#sendBody
 */
@Component
public class SsrfRoute extends RouteBuilder {

    @Override
    public void configure() throws Exception {
        // Route 1: SSRF via query param - GET /api/fetch?url=...
        from("servlet:/fetch?httpMethodRestrict=GET")
            .routeId("ssrf-query-param")
            .process(exchange -> {
                Message message = exchange.getMessage();
                // VULN: user-controlled URL forwarded directly to HTTP component
                String targetUrl = message.getHeader("url", String.class);
                message.setHeader(Exchange.HTTP_URI, targetUrl);
                message.setHeader(Exchange.HTTP_METHOD, "GET");
            })
            .to("http://placeholder?bridgeEndpoint=true&throwExceptionOnFailure=false")
            .process(exchange -> {
                Message message = exchange.getMessage();
                String response = message.getBody(String.class);
                message.setBody(response);
            });

        // Route 2: SSRF via header - GET /api/proxy with X-Target-Url header
        from("servlet:/proxy?httpMethodRestrict=GET")
            .routeId("ssrf-header")
            .process(exchange -> {
                Message message = exchange.getMessage();
                // VULN: target URL read from arbitrary request header
                String targetUrl = message.getHeader("X-Target-Url", String.class);
                String proxyPath = message.getHeader("X-Path", String.class);
                message.setHeader(Exchange.HTTP_URI, targetUrl + proxyPath);
            })
            .to("http://placeholder?bridgeEndpoint=true&throwExceptionOnFailure=false")
            .process(exchange -> {
                Message message = exchange.getMessage();
                message.setBody(message.getBody(String.class));
            });

        // Route 3: SSRF with ExchangeBuilder
        from("servlet:/forward?httpMethodRestrict=POST")
            .routeId("ssrf-exchange-builder")
            .process(exchange -> {
                Message message = exchange.getMessage();
                String targetUrl = message.getBody(String.class);
                // VULN: URL from body passed via ExchangeBuilder
                Exchange forwardExchange = ExchangeBuilder.anExchange(exchange.getContext())
                        .withBody("")
                        .withHeader(Exchange.HTTP_URI, targetUrl)
                        .withHeader(Exchange.HTTP_METHOD, "GET")
                        .build();
                Exchange result = exchange.getContext().createProducerTemplate()
                        .send("http://placeholder?bridgeEndpoint=true&throwExceptionOnFailure=false",
                                forwardExchange);
                message.setBody(result.getMessage().getBody(String.class));
            });
    }
}
