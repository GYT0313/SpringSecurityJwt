package org.example.jwt.security.config;

import org.example.jwt.security.filter.CustomUsernamePasswordAuthenticationFilter;
import org.example.jwt.security.handler.UserLoginFailureHandler;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;

/**
 * <p>  <br>
 *
 * @author GuYongtao
 * @date 2022/1/14
 * @since 1.0
 */
public class UserLoginConfigurer<T extends UserLoginConfigurer<T, B>, B extends HttpSecurityBuilder<B>>
        extends AbstractHttpConfigurer<T, B> {

    private final CustomUsernamePasswordAuthenticationFilter authenticationFilter;

    public UserLoginConfigurer() {
        this.authenticationFilter = new CustomUsernamePasswordAuthenticationFilter();
    }


    @Override
    public void configure(B builder) {
        // 设置filter使用公共的AuthenticationManager
        authenticationFilter.setAuthenticationManager(builder.getSharedObject(AuthenticationManager.class));
        // 设置认证失败handler 和 认证后的context不放入session
        authenticationFilter.setAuthenticationFailureHandler(new UserLoginFailureHandler());
        authenticationFilter.setSessionAuthenticationStrategy(new NullAuthenticatedSessionStrategy());

        CustomUsernamePasswordAuthenticationFilter filter = postProcess(authenticationFilter);
        // 指定filter位置
        builder.addFilterAfter(filter, LogoutFilter.class);
    }


    /**
     * <p> 设置认证成功handler, 并返回UserLoginConfigurer <br>
     *
     * @param authenticationSuccessHandler 登陆成功handler
     * @return org.example.security.config.UserLoginConfigurer<T, B>
     */
    public UserLoginConfigurer<T, B> setLoginSuccessHandlerAndReturn(AuthenticationSuccessHandler authenticationSuccessHandler) {
        authenticationFilter.setAuthenticationSuccessHandler(authenticationSuccessHandler);
        return this;
    }
}
