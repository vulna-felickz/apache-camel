package com.example;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Initializes the in-memory H2 database with sample tables and data.
 */
@Configuration
public class DatabaseConfig {

    @Bean
    public CommandLineRunner initDatabase(JdbcTemplate jdbc) {
        return args -> {
            jdbc.execute("CREATE TABLE IF NOT EXISTS users (" +
                    "id INT AUTO_INCREMENT PRIMARY KEY, " +
                    "name VARCHAR(255), " +
                    "email VARCHAR(255), " +
                    "password VARCHAR(255))");

            jdbc.execute("CREATE TABLE IF NOT EXISTS items (" +
                    "id INT AUTO_INCREMENT PRIMARY KEY, " +
                    "data VARCHAR(1000), " +
                    "category VARCHAR(255))");

            jdbc.execute("INSERT INTO users (name, email, password) VALUES " +
                    "('alice', 'alice@example.com', 'secret1')");  // demo only — production must hash passwords
            jdbc.execute("INSERT INTO users (name, email, password) VALUES " +
                    "('bob', 'bob@example.com', 'secret2')");
            jdbc.execute("INSERT INTO users (name, email, password) VALUES " +
                    "('admin', 'admin@example.com', 'admin123')");
        };
    }
}
