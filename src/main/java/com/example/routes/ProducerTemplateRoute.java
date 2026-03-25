package com.example.routes;

import org.apache.camel.Exchange;
import org.apache.camel.Message;
import org.apache.camel.ProducerTemplate;
import org.apache.camel.builder.ExchangeBuilder;
import org.apache.camel.builder.RouteBuilder;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.util.Base64;

/**
 * Demonstrates ProducerTemplate sendBody variants and ExchangeBuilder usage
 * for CodeQL taint-tracking modeling. Also includes an unsafe deserialization sink.
 *
 * Demonstrates:
 *   - ProducerTemplate#sendBody(String, Object)
 *   - ProducerTemplate#sendBodyAndHeader(String, Object, String, Object)
 *   - ProducerTemplate#sendBodyAndHeaders(String, Object, Map)
 *   - ExchangeBuilder#withBody(Object)
 *   - ExchangeBuilder#withHeader(String, Object)
 *   - Message#getBody(Class)
 *   - Message#getHeader(String, Class)
 *   - Exchange#getMessage()
 */
@Component
public class ProducerTemplateRoute extends RouteBuilder {

    @Override
    public void configure() throws Exception {
        // Entry point: POST /api/process
        from("servlet:/process?httpMethodRestrict=POST")
            .routeId("producer-template-entry")
            .process(exchange -> {
                Message message = exchange.getMessage();
                String body = message.getBody(String.class);
                String action = message.getHeader("X-Action", String.class);

                ProducerTemplate template = exchange.getContext().createProducerTemplate();

                if ("log".equals(action)) {
                    // VULN: user body sent via sendBody to internal logging route
                    template.sendBody("direct:logData", body);
                    message.setBody("logged");
                } else if ("store".equals(action)) {
                    // VULN: user body + header sent via sendBodyAndHeader
                    String category = message.getHeader("X-Category", String.class);
                    template.sendBodyAndHeader("direct:storeData", body, "category", category);
                    message.setBody("stored");
                } else {
                    // VULN: tainted body sent via ExchangeBuilder into processing route
                    Exchange newExchange = ExchangeBuilder.anExchange(exchange.getContext())
                            .withBody(body)
                            .withHeader("source", "user-input")
                            .build();
                    Exchange result = template.send("direct:processData", newExchange);
                    message.setBody(result.getMessage().getBody(String.class));
                }
            });

        // Internal route: receives tainted data via ProducerTemplate
        from("direct:logData")
            .routeId("log-data-sink")
            .process(exchange -> {
                Message message = exchange.getMessage();
                // VULN: tainted data from ProducerTemplate sendBody reaches this sink
                String data = message.getBody(String.class);
                // log injection: unsanitized user data written to logs
                org.slf4j.LoggerFactory.getLogger(ProducerTemplateRoute.class).info("Data: " + data);
            });

        // Internal route: stores data (SQL injection sink via ProducerTemplate)
        from("direct:storeData")
            .routeId("store-data-sink")
            .process(exchange -> {
                Message message = exchange.getMessage();
                String data = message.getBody(String.class);
                String category = message.getHeader("category", String.class);
                // VULN: tainted data from sendBodyAndHeader used in SQL
                String sql = "INSERT INTO items (data, category) VALUES ('" + data + "', '" + category + "')";
                // execution would happen here
                message.setBody("Stored: " + sql);
            });

        // Internal route: processes data (command injection sink)
        from("direct:processData")
            .routeId("process-data-sink")
            .process(exchange -> {
                Message message = exchange.getMessage();
                String data = message.getBody(String.class);
                // VULN: tainted data from ExchangeBuilder route used in exec
                String[] cmd = {"/bin/sh", "-c", "echo " + data};
                Process p = Runtime.getRuntime().exec(cmd);
                message.setBody("processed");
            });

        // Route: unsafe deserialization - POST /api/deserialize
        from("servlet:/deserialize?httpMethodRestrict=POST")
            .routeId("unsafe-deserialization")
            .process(exchange -> {
                Message message = exchange.getMessage();
                // VULN: base64-encoded serialized object from body deserialized without checks
                String base64Data = message.getBody(String.class);
                byte[] bytes = Base64.getDecoder().decode(base64Data.trim());
                try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes))) {
                    Object obj = ois.readObject();
                    message.setBody("Deserialized: " + obj.getClass().getName());
                }
            });

        // Route: demonstrating sendBodyAndHeaders with map from user input
        from("servlet:/bulk?httpMethodRestrict=POST")
            .routeId("producer-send-body-and-headers")
            .process(exchange -> {
                Message message = exchange.getMessage();
                String body = message.getBody(String.class);
                // Build a headers map that includes user-controlled values
                java.util.Map<String, Object> headers = new java.util.HashMap<>();
                headers.put("user-data", body);
                headers.put("X-Forwarded-For", message.getHeader("X-Forwarded-For", String.class));
                headers.put("X-Custom", message.getHeader("X-Custom", String.class));

                ProducerTemplate template = exchange.getContext().createProducerTemplate();
                // VULN: user-controlled headers propagated to internal route
                template.sendBodyAndHeaders("direct:storeData", body, headers);
                message.setBody("dispatched");
            });
    }
}
