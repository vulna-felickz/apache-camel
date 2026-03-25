package com.example.routes;

import org.apache.camel.Exchange;
import org.apache.camel.Message;
import org.apache.camel.Processor;
import org.apache.camel.ProducerTemplate;
import org.apache.camel.builder.RouteBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.stream.Collectors;

/**
 * Demonstrates explicit named Processor implementations and @Autowired ProducerTemplate.
 *
 * CodeQL needs to see:
 *   (a) Named classes that implement org.apache.camel.Processor — so it can model
 *       Processor#process(Exchange) as a taint-propagation step from the Camel runtime
 *       into user code.
 *   (b) ProducerTemplate obtained via Spring @Autowired injection — the most common
 *       pattern in real apps, distinct from createProducerTemplate().
 *
 * Demonstrates:
 *   - Processor (named implementation)
 *   - Exchange#getMessage()
 *   - Message#getBody(Class)
 *   - Message#getHeader(String, Class)
 *   - Message#getHeader(String)        (untyped overload)
 *   - Message#setBody(Object)
 *   - Message#setHeader(String, Object)
 *   - ProducerTemplate#sendBody (via @Autowired injection)
 *   - ProducerTemplate#requestBody (request/reply variant)
 */
@Component
public class ProcessorAndAutowiredTemplateRoute extends RouteBuilder {

    /** @Autowired ProducerTemplate — common Spring Boot injection pattern. */
    @Autowired
    private ProducerTemplate producerTemplate;

    @Override
    public void configure() throws Exception {
        // Route 1: uses an explicit Processor bean for SQL injection
        //   GET /api/lookup?id=...
        from("servlet:/lookup?httpMethodRestrict=GET")
            .routeId("processor-sql-injection")
            .process(new SqlLookupProcessor());

        // Route 2: uses an explicit Processor that reads body and calls sendBody
        //   POST /api/notify
        from("servlet:/notify?httpMethodRestrict=POST")
            .routeId("processor-notify")
            .process(new NotifyDispatchProcessor());

        // Route 3: @Autowired ProducerTemplate used directly in a processor
        //   POST /api/trigger
        from("servlet:/trigger?httpMethodRestrict=POST")
            .routeId("autowired-template-trigger")
            .process(exchange -> {
                Message message = exchange.getMessage();
                String payload = message.getBody(String.class);
                String target = message.getHeader("X-Target", String.class);
                // VULN: user payload sent via @Autowired ProducerTemplate
                producerTemplate.sendBody("direct:" + target, payload);
                message.setBody("triggered");
            });

        // Route 4: ProducerTemplate#requestBody (request/reply)
        //   POST /api/evaluate
        from("servlet:/evaluate?httpMethodRestrict=POST")
            .routeId("autowired-template-request-body")
            .process(exchange -> {
                Message message = exchange.getMessage();
                String expr = message.getBody(String.class);
                // VULN: user expression sent via requestBody; reply returned
                Object result = producerTemplate.requestBody("direct:evalExpr", expr);
                message.setBody(result);
            });

        // Internal route: receives tainted payload via requestBody
        from("direct:evalExpr")
            .routeId("eval-expr-sink")
            .process(exchange -> {
                Message message = exchange.getMessage();
                String expr = message.getBody(String.class);
                // VULN: expression from user input executed as shell command
                String[] cmd = {"/bin/sh", "-c", expr};
                Process p = Runtime.getRuntime().exec(cmd);
                String out = new BufferedReader(new InputStreamReader(p.getInputStream()))
                        .lines().collect(Collectors.joining("\n"));
                message.setBody(out);
            });
    }

    // -------------------------------------------------------------------------
    // Explicit named Processor implementations
    // -------------------------------------------------------------------------

    /**
     * Named Processor: reads the "id" header (untyped overload) and uses it in SQL.
     *
     * Demonstrates Processor interface + Message#getHeader(String) untyped overload.
     */
    @Component
    public static class SqlLookupProcessor implements Processor {
        @Override
        public void process(Exchange exchange) throws Exception {
            Message message = exchange.getMessage();
            // getHeader(String) — untyped overload; returns Object
            Object rawId = message.getHeader("id");
            // VULN: unsanitized id concatenated directly into SQL query
            String sql = "SELECT * FROM users WHERE id = " + rawId;
            message.setBody(sql);  // body carries the tainted SQL string
            message.setHeader("X-Executed-Query", sql);
        }
    }

    /**
     * Named Processor: reads body and header, propagates via ProducerTemplate.
     *
     * Demonstrates Processor interface + Message#getBody(Class) +
     * Message#getHeader(String, Class) + ProducerTemplate#sendBody (autowired).
     */
    @Component
    public static class NotifyDispatchProcessor implements Processor {

        @Autowired
        private ProducerTemplate producerTemplate;

        @Override
        public void process(Exchange exchange) throws Exception {
            Message message = exchange.getMessage();
            String body = message.getBody(String.class);
            String channel = message.getHeader("X-Channel", String.class);
            // VULN: user body forwarded via sendBody to a channel derived from header
            producerTemplate.sendBody("direct:" + channel, body);
            message.setBody("dispatched to " + channel);
        }
    }
}
