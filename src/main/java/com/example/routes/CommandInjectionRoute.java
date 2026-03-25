package com.example.routes;

import org.apache.camel.Exchange;
import org.apache.camel.Message;
import org.apache.camel.ProducerTemplate;
import org.apache.camel.builder.ExchangeBuilder;
import org.apache.camel.builder.RouteBuilder;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.stream.Collectors;

/**
 * Command Injection vulnerability via Camel message body.
 *
 * Demonstrates:
 *   - Exchange#getMessage()
 *   - Message#getBody(Class)
 *   - Message#setBody(Object)
 *   - ProducerTemplate#sendBody
 *   - ExchangeBuilder#withBody(Object)
 */
@Component
public class CommandInjectionRoute extends RouteBuilder {

    @Override
    public void configure() throws Exception {
        // Route 1: Command injection via POST body - POST /api/ping
        from("servlet:/ping?httpMethodRestrict=POST")
            .routeId("command-injection-body")
            .process(exchange -> {
                Message message = exchange.getMessage();
                // VULN: user input from body concatenated into shell command
                String host = message.getBody(String.class);
                String[] cmd = {"/bin/sh", "-c", "ping -c 1 " + host};
                Process process = Runtime.getRuntime().exec(cmd);
                String output = new BufferedReader(new InputStreamReader(process.getInputStream()))
                        .lines().collect(Collectors.joining("\n"));
                message.setBody(output);
            });

        // Route 2: Command injection via header - GET /api/exec with X-Command header
        from("servlet:/exec?httpMethodRestrict=GET")
            .routeId("command-injection-header")
            .process(exchange -> {
                Message message = exchange.getMessage();
                // VULN: command from header executed directly
                String cmd = message.getHeader("X-Command", String.class);
                Process process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
                String output = new BufferedReader(new InputStreamReader(process.getInputStream()))
                        .lines().collect(Collectors.joining("\n"));
                message.setBody(output);
            });

        // Route 3: Using ProducerTemplate to send to an exec route
        from("direct:runCommand")
            .routeId("command-via-producer")
            .process(exchange -> {
                Message message = exchange.getMessage();
                String cmd = message.getBody(String.class);
                String[] shellCmd = {"/bin/sh", "-c", cmd};
                Process process = Runtime.getRuntime().exec(shellCmd);
                String output = new BufferedReader(new InputStreamReader(process.getInputStream()))
                        .lines().collect(Collectors.joining("\n"));
                message.setBody(output);
            });

        // Route 4: ExchangeBuilder usage - builds an exchange with tainted body and sends it
        from("servlet:/dispatch?httpMethodRestrict=POST")
            .routeId("exchange-builder-dispatch")
            .process(exchange -> {
                Message message = exchange.getMessage();
                String userInput = message.getBody(String.class);
                // VULN: user input flows via ExchangeBuilder into another route
                ProducerTemplate template = exchange.getContext().createProducerTemplate();
                Exchange newExchange = ExchangeBuilder.anExchange(exchange.getContext())
                        .withBody(userInput)
                        .build();
                Exchange result = template.send("direct:runCommand", newExchange);
                message.setBody(result.getMessage().getBody(String.class));
            });
    }
}
