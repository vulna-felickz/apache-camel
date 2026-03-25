package com.example;

import org.apache.camel.CamelContext;
import org.apache.camel.ProducerTemplate;
import org.apache.camel.test.spring.junit5.CamelSpringBootTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.http.*;

import static org.assertj.core.api.Assertions.assertThat;

@CamelSpringBootTest
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class CamelVulnAppTest {

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private CamelContext camelContext;

    private String baseUrl() {
        return "http://localhost:" + port + "/api";
    }

    @Test
    public void contextLoads() {
        assertThat(camelContext).isNotNull();
        assertThat(camelContext.getRoutes()).isNotEmpty();
    }

    @Test
    public void sqlInjectionRouteIsReachable() {
        ResponseEntity<String> response = restTemplate.getForEntity(
                baseUrl() + "/users?name=alice", String.class);
        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(response.getBody()).contains("alice");
    }

    @Test
    public void sqlInjectionPostRouteIsReachable() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.TEXT_PLAIN);
        ResponseEntity<String> response = restTemplate.postForEntity(
                baseUrl() + "/search",
                new HttpEntity<>("example.com", headers),
                String.class);
        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
    }

    @Test
    public void xssRouteIsReachable() {
        ResponseEntity<String> response = restTemplate.getForEntity(
                baseUrl() + "/greet?name=World", String.class);
        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(response.getBody()).contains("World");
    }

    @Test
    public void xssPostBodyRouteIsReachable() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.TEXT_PLAIN);
        ResponseEntity<String> response = restTemplate.postForEntity(
                baseUrl() + "/comment",
                new HttpEntity<>("Hello World", headers),
                String.class);
        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(response.getBody()).contains("Hello World");
    }

    @Test
    public void xxeRouteIsReachable() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.TEXT_XML);
        String xml = "<?xml version=\"1.0\"?><root>test</root>";
        ResponseEntity<String> response = restTemplate.postForEntity(
                baseUrl() + "/xml/parse",
                new HttpEntity<>(xml, headers),
                String.class);
        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(response.getBody()).contains("root");
    }

    @Test
    public void statusRouteIsReachable() {
        HttpHeaders headers = new HttpHeaders();
        headers.set("X-User", "testuser");
        headers.set("X-Request-Id", "req-001");
        ResponseEntity<String> response = restTemplate.exchange(
                baseUrl() + "/status",
                HttpMethod.GET,
                new HttpEntity<>(headers),
                String.class);
        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
    }

    @Test
    public void allRoutesRegistered() {
        // Verify all vulnerable routes are loaded
        assertThat(camelContext.getRoute("sql-injection-body")).isNotNull();
        assertThat(camelContext.getRoute("sql-injection-post-body")).isNotNull();
        assertThat(camelContext.getRoute("path-traversal-header")).isNotNull();
        assertThat(camelContext.getRoute("path-traversal-query")).isNotNull();
        assertThat(camelContext.getRoute("command-injection-body")).isNotNull();
        assertThat(camelContext.getRoute("command-injection-header")).isNotNull();
        assertThat(camelContext.getRoute("exchange-builder-dispatch")).isNotNull();
        assertThat(camelContext.getRoute("ssrf-query-param")).isNotNull();
        assertThat(camelContext.getRoute("ssrf-header")).isNotNull();
        assertThat(camelContext.getRoute("ssrf-exchange-builder")).isNotNull();
        assertThat(camelContext.getRoute("xss-reflected")).isNotNull();
        assertThat(camelContext.getRoute("log-injection")).isNotNull();
        assertThat(camelContext.getRoute("header-injection")).isNotNull();
        assertThat(camelContext.getRoute("xss-stored-body")).isNotNull();
        assertThat(camelContext.getRoute("xxe-body")).isNotNull();
        assertThat(camelContext.getRoute("xxe-with-header-schema")).isNotNull();
        assertThat(camelContext.getRoute("producer-template-entry")).isNotNull();
        assertThat(camelContext.getRoute("unsafe-deserialization")).isNotNull();
        assertThat(camelContext.getRoute("producer-send-body-and-headers")).isNotNull();
    }
}
