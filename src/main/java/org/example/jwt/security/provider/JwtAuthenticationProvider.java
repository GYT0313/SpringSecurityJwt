package org.example.jwt.security.provider;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.example.jwt.security.entity.JwtAuthenticationToken;
import org.example.jwt.security.service.JwtUserServiceImpl;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.www.NonceExpiredException;

import java.util.Calendar;
import java.util.Objects;

/**
 * <p> jwt认证提供类 <br>
 *
 * @author GuYongtao
 * @date 2022/1/13
 * @since 1.0
 */
public class JwtAuthenticationProvider implements AuthenticationProvider {

    private final JwtUserServiceImpl jwtUserServiceImpl;


    public JwtAuthenticationProvider(JwtUserServiceImpl jwtUserServiceImpl) {
        this.jwtUserServiceImpl = jwtUserServiceImpl;
    }


    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        DecodedJWT jwt = ((JwtAuthenticationToken) authentication).getDecodedJWT();
        if (Calendar.getInstance().getTime().after(jwt.getExpiresAt())) {
            throw new NonceExpiredException("Token expires.");
        }

        String username = jwt.getSubject();
        JwtAuthenticationToken jat = jwtUserServiceImpl.getUserLoginInfo(username);
        if (Objects.isNull(jat.getPrincipal()) || Objects.isNull(jat.getPrincipal().getPassword())) {
            throw new NonceExpiredException("Token expires.");
        }
        String encryptSalt = jat.getPrincipal().getPassword();
        try {
            Algorithm algorithm = Algorithm.HMAC256(encryptSalt);
            JWTVerifier verifier = JWT.require(algorithm).withSubject(jat.getPrincipal().getUsername()).build();
            // 请求中的authentication与redis对比
            verifier.verify(jwt.getToken());
            if (!Objects.equals(jwt.getToken(), jat.getDecodedJWT().getToken())) {
                throw new BadCredentialsException(username + " - Token 不匹配.");
            }
        } catch (Exception e) {
            throw new BadCredentialsException(username + " - Token 认证失败.", e);
        }

        return new JwtAuthenticationToken(jat.getPrincipal(), jwt, jat.getPrincipal().getAuthorities());
    }


    @Override
    public boolean supports(Class<?> authentication) {
        return JwtAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
