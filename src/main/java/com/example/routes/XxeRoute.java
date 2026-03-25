package com.example.routes;

import org.apache.camel.Exchange;
import org.apache.camel.Message;
import org.apache.camel.builder.RouteBuilder;
import org.springframework.stereotype.Component;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

/**
 * XXE (XML External Entity) vulnerability via Camel message body.
 *
 * Demonstrates:
 *   - Exchange#getMessage()
 *   - Message#getBody(Class)
 *   - Message#setBody(Object)
 */
@Component
public class XxeRoute extends RouteBuilder {

    @Override
    public void configure() throws Exception {
        // Route 1: XXE via POST body - POST /api/xml/parse
        from("servlet:/xml/parse?httpMethodRestrict=POST")
            .routeId("xxe-body")
            .process(exchange -> {
                Message message = exchange.getMessage();
                // VULN: XML body parsed with external entities enabled
                String xmlInput = message.getBody(String.class);
                DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
                // intentionally not disabling external entities (XXE)
                DocumentBuilder builder = factory.newDocumentBuilder();
                org.w3c.dom.Document doc = builder.parse(
                        new ByteArrayInputStream(xmlInput.getBytes(StandardCharsets.UTF_8)));
                String rootElement = doc.getDocumentElement().getNodeName();
                String textContent = doc.getDocumentElement().getTextContent();
                message.setBody("Root: " + rootElement + ", Content: " + textContent);
            });

        // Route 2: XXE with content from header - POST /api/xml/transform
        from("servlet:/xml/transform?httpMethodRestrict=POST")
            .routeId("xxe-with-header-schema")
            .process(exchange -> {
                Message message = exchange.getMessage();
                // VULN: XML from body + schema URL from header, both user-controlled
                String xmlInput = message.getBody(String.class);
                String schemaUrl = message.getHeader("X-Schema-Url", String.class);
                DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
                // intentionally not disabling external entities (XXE)
                factory.setAttribute("http://java.sun.com/xml/jaxp/properties/schemaLanguage",
                        "http://www.w3.org/2001/XMLSchema");
                if (schemaUrl != null) {
                    factory.setAttribute("http://java.sun.com/xml/jaxp/properties/schemaSource", schemaUrl);
                }
                DocumentBuilder builder = factory.newDocumentBuilder();
                org.w3c.dom.Document doc = builder.parse(
                        new ByteArrayInputStream(xmlInput.getBytes(StandardCharsets.UTF_8)));
                message.setBody(doc.getDocumentElement().getTextContent());
            });
    }
}
