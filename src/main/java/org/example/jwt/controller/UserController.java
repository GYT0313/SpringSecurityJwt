package org.example.jwt.controller;

import org.example.jwt.entity.User;
import org.example.jwt.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

/**
 * <p>  <br>
 *
 * @author GuYongtao
 * @date 2022/1/14
 * @since 1.0
 */
@RestController
public class UserController {

    @Autowired
    private UserService userService;


    @PostMapping("/get/{username}")
    public Optional<User> findUserByUsername(String username) {
        return userService.findUserByUsername(username);
    }


    @GetMapping("/home")
    @PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_USER')")
    public String homepage() {
        return "home";
    }

}
