package com.example.routes;

import org.apache.camel.Exchange;
import org.apache.camel.Message;
import org.apache.camel.builder.RouteBuilder;
import org.springframework.stereotype.Component;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * Path Traversal vulnerability via Camel message headers and body.
 *
 * Demonstrates:
 *   - Exchange#getMessage()
 *   - Message#getHeader(String, Class)
 *   - Message#getHeader(String)        (untyped overload — returns Object)
 *   - Message#setBody(Object)
 */
@Component
public class PathTraversalRoute extends RouteBuilder {

    @Override
    public void configure() throws Exception {
        // Route 1: Path traversal via header - GET /api/file with X-File-Path header
        from("servlet:/file?httpMethodRestrict=GET")
            .routeId("path-traversal-header")
            .process(exchange -> {
                Message message = exchange.getMessage();
                // VULN: file path from header used directly without sanitization
                String filePath = message.getHeader("X-File-Path", String.class);
                String baseDir = "/var/data/";
                byte[] content = Files.readAllBytes(Paths.get(baseDir + filePath));
                message.setBody(new String(content));
            });

        // Route 2: Path traversal via query param - GET /api/download?filename=...
        from("servlet:/download?httpMethodRestrict=GET")
            .routeId("path-traversal-query")
            .process(exchange -> {
                Message message = exchange.getMessage();
                // VULN: filename from request used to build file path
                // getHeader(String) — untyped overload, returns Object; cast to String
                String filename = (String) message.getHeader("filename");
                File file = new File("/uploads/" + filename);
                message.setBody(file.exists() ? new String(Files.readAllBytes(file.toPath())) : "not found");
            });
    }
}
