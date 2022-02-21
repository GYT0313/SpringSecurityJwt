package org.example.jwt.service;

import org.example.jwt.dao.UserMapper;
import org.example.jwt.entity.User;
import org.springframework.stereotype.Service;

import java.util.Optional;

/**
 * <p>  <br>
 *
 * @author GuYongtao
 * @date 2022/1/12
 * @since 1.0
 */
@Service
public class UserService {

    private final UserMapper userMapper;

    public UserService(UserMapper userMapper) {
        this.userMapper = userMapper;
    }


    /**
     * <p> 根据用户名查询用户信息 </br>
     *
     * @param username 用户名
     * @return 用户信息
     */
    public Optional<User> findUserByUsername(String username) {
        return userMapper.findUserByUsername(username);
    }


}
