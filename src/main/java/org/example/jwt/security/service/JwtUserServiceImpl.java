package org.example.jwt.security.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.example.jwt.dao.UserMapper;
import org.example.jwt.security.common.AuthorizationConstants;
import org.example.jwt.security.entity.JwtAuthenticationToken;
import org.example.jwt.security.entity.RedisInfo;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

/**
 * <p> 密码校验 <br>
 *
 * @author GuYongtao
 * @date 2022/1/13
 * @since 1.0
 */
@Service
public class JwtUserServiceImpl implements UserDetailsService {

    private final UserMapper userMapper;

    private final RedisTemplate<String, Object> redisTemplate;

    private final PasswordEncoder passwordEncoder;


    public JwtUserServiceImpl(UserMapper userMapper, RedisTemplate<String, Object> redisTemplate) {
        this.userMapper = userMapper;
        this.redisTemplate = redisTemplate;
        this.passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // TODO: 数据库密码校验
        Optional<org.example.jwt.entity.User> userOptional = findUserByUsername(username);
        if (!userOptional.isPresent()) {
            throw new BadCredentialsException("Mysql not found user - " + username);
        }
        String encode = passwordEncoder.encode(userOptional.get().getPassword());
        return User.builder().username(username).password(encode).roles(userOptional.get().getRole()).build();
    }


    /**
     * <p> 根据用户名差用户信息 </br>
     *
     * @param username usernmae
     * @return java.lang.String
     */
    public Optional<org.example.jwt.entity.User> findUserByUsername(String username) {
        return userMapper.findUserByUsername(username);
    }

    /**
     * <p> 新建token, token存入redis <br>
     *
     * @param userDetails x
     * @return java.lang.String
     */
    public String saveUserLoginInfo(UserDetails userDetails) {
        // 从mysql获取用户数据
        Optional<org.example.jwt.entity.User> userOptional = findUserByUsername(userDetails.getUsername());
        if (!userOptional.isPresent()) {
            throw new BadCredentialsException("Mysql not found user - " + userDetails.getUsername());
        }
        String salt = passwordEncoder.encode(userOptional.get().getPassword());

        Algorithm algorithm = Algorithm.HMAC256(salt);
        // 设置token有效时间
        Date date = new Date(System.currentTimeMillis() + AuthorizationConstants.TOKEN_TTL_SECONDS * 1000);
        String token = JWT.create()
                .withSubject(userDetails.getUsername())
                .withExpiresAt(date)
                .withIssuedAt(new Date())
                .sign(algorithm);
        // 设置用户信息、token到redis
        redisTemplate.opsForValue().set(userDetails.getUsername(), new RedisInfo(
                        userOptional.get().getId(), salt, token),
                AuthorizationConstants.REDIS_TOKEN_TTL_SECONDS, TimeUnit.SECONDS);
        return token;
    }


    /**
     * <p> 从redis获取用户信息 <br>
     *
     * @param username 用户名
     * @return 用户
     */
    public JwtAuthenticationToken getUserLoginInfo(String username) {
        UserDetails userDetails = loadUserByUsername(username);
        Optional<Object> infoByRedisOptional = Optional.ofNullable(redisTemplate.opsForValue().get(username));
        if (!infoByRedisOptional.isPresent()) {
            throw new BadCredentialsException("Redis not found username: " + username);
        }
        RedisInfo redisInfo = (RedisInfo) infoByRedisOptional.get();
        UserDetails principal = User.builder().username(userDetails.getUsername()).password(
                redisInfo.getPasswordSalt()).authorities(userDetails.getAuthorities()).build();

        return new JwtAuthenticationToken(principal, JWT.decode(redisInfo.getToken()), userDetails.getAuthorities());
    }


    /**
     * <p> 清除数据库或者缓存中登录salt <br>
     *
     * @param username 用户名
     */
    public void deleteUserLoginInfo(String username) {
        // TODO 清除数据库或者缓存中登录salt
    }

}
