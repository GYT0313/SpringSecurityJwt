package org.example.jwt.security.config;

import org.example.jwt.security.filter.JwtAuthenticationFilter;
import org.example.jwt.security.handler.UserLoginFailureHandler;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutFilter;

/**
 * <p> 初始化JWTFilter <br>
 *
 * @author GuYongtao
 * @date 2022/1/13
 * @since 1.0
 */
public class JwtLoginConfigurer<T extends JwtLoginConfigurer<T, B>, B extends HttpSecurityBuilder<B>>
        extends AbstractHttpConfigurer<T, B> {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    public JwtLoginConfigurer() {
        this.jwtAuthenticationFilter = new JwtAuthenticationFilter();
    }


    @Override
    public void configure(B builder) {
        jwtAuthenticationFilter.setAuthenticationManager(builder.getSharedObject(AuthenticationManager.class));
        jwtAuthenticationFilter.setFailureHandler(new UserLoginFailureHandler());
        builder.addFilterAfter(postProcess(this.jwtAuthenticationFilter), LogoutFilter.class);
    }


    /**
     * <p> 设置匿名用户可访问url  <br>
     *
     * @param urls 匿名白名单
     * @return org.example.security.config.JwtLoginConfigurer<T, B>
     */
    public JwtLoginConfigurer<T, B> permissiveRequestUrls(String... urls) {
        jwtAuthenticationFilter.setPermissiveUrl(urls);
        return this;
    }

    public JwtLoginConfigurer<T, B> tokenValidSuccessHandler(AuthenticationSuccessHandler successHandler) {
        jwtAuthenticationFilter.setSuccessHandler(successHandler);
        return this;
    }
}
