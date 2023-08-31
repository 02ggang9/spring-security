package com.example.springSecurity2;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;

@SpringBootApplication(exclude = DataSourceAutoConfiguration.class)
public class SpringSecurity2Application {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurity2Application.class, args);
	}

}
