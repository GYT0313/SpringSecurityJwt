package org.example.jwt.dao;

import org.apache.ibatis.annotations.Mapper;
import org.example.jwt.entity.User;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

/**
 * <p>  <br>
 *
 * @author GuYongtao
 * @date 2022/1/12
 * @since 1.0
 */
@Mapper
public interface UserMapper {

    /**
     * <p> 根据用户名查询用户信息 <br>
     *
     * @param username 用户名
     * @return 用户信息
     */
    Optional<User> findUserByUsername(@Param("username") String username);

}
