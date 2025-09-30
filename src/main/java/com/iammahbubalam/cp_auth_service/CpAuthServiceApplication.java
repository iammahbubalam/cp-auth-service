package com.iammahbubalam.cp_auth_service;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.data.r2dbc.config.EnableR2dbcAuditing;
import org.springframework.transaction.annotation.EnableTransactionManagement;


@EnableCaching
@EnableR2dbcAuditing
@EnableTransactionManagement
@SpringBootApplication
public class CpAuthServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(CpAuthServiceApplication.class, args);
    }

}
