package org.example.jwt.entity;

import lombok.Getter;
import lombok.Setter;

/**
 * <p>  <br>
 *
 * @author GuYongtao
 * @date 2022/1/12
 * @since 1.0
 */
@Getter
@Setter
public class User {

    private Integer id;

    private String username;

    private String password;

    private String role;
}
