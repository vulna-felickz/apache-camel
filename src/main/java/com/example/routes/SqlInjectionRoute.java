package com.example.routes;

import org.apache.camel.Exchange;
import org.apache.camel.Message;
import org.apache.camel.builder.RouteBuilder;
import org.springframework.stereotype.Component;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

/**
 * SQL Injection vulnerability via Camel message body and headers.
 *
 * Demonstrates:
 *   - Exchange#getMessage()
 *   - Message#getBody(Class)
 *   - Message#getHeader(String)
 *   - Message#setBody(Object)
 */
@Component
public class SqlInjectionRoute extends RouteBuilder {

    private final DataSource dataSource;

    public SqlInjectionRoute(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @Override
    public void configure() throws Exception {
        // Route 1: SQL injection via body - GET /api/users?name=...
        from("servlet:/users?httpMethodRestrict=GET")
            .routeId("sql-injection-body")
            .process(exchange -> {
                Message message = exchange.getMessage();
                // VULN: user input from query param flows into raw SQL
                String name = message.getHeader("name", String.class);
                String sql = "SELECT * FROM users WHERE name = '" + name + "'";
                List<String> results = new ArrayList<>();
                try (Connection conn = dataSource.getConnection();
                     Statement stmt = conn.createStatement();
                     ResultSet rs = stmt.executeQuery(sql)) {
                    while (rs.next()) {
                        results.add(rs.getString("name") + ":" + rs.getString("email"));
                    }
                }
                message.setBody(results.toString());
            });

        // Route 2: SQL injection via POST body
        from("servlet:/search?httpMethodRestrict=POST")
            .routeId("sql-injection-post-body")
            .process(exchange -> {
                Message message = exchange.getMessage();
                // VULN: body from POST used directly in SQL
                String query = message.getBody(String.class);
                String sql = "SELECT * FROM users WHERE email LIKE '%" + query + "%'";
                List<String> results = new ArrayList<>();
                try (Connection conn = dataSource.getConnection();
                     Statement stmt = conn.createStatement();
                     ResultSet rs = stmt.executeQuery(sql)) {
                    while (rs.next()) {
                        results.add(rs.getString("name") + ":" + rs.getString("email"));
                    }
                }
                message.setBody(results.toString());
            });
    }
}
