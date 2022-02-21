package org.example.jwt;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;

/**
 * <p>  <br>
 * @author GuYongtao
 * @since 1.0
 * @date 2022/1/12
 */
@SpringBootApplication
@MapperScan(basePackages = {"org.example.jwt.dao"})
@EnableGlobalMethodSecurity(prePostEnabled=true)
public class App {
    public static void main(String[] args) {
        SpringApplication.run(App.class, args);
    }
}
