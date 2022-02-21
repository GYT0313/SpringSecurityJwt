package org.example.jwt.security.config;

import org.example.jwt.security.common.AuthorizationConstants;
import org.example.jwt.security.filter.OptionsRequestFilter;
import org.example.jwt.security.handler.TokenClearLogoutHandler;
import org.example.jwt.security.handler.UserLoginSuccessHandler;
import org.example.jwt.security.provider.JwtAuthenticationProvider;
import org.example.jwt.security.service.JwtUserServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;
import org.springframework.security.web.header.Header;
import org.springframework.security.web.header.writers.StaticHeadersWriter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.util.Arrays;

/**
 * <p> Security配置 <br>
 *
 * @author GuYongtao
 * @date 2022/1/13
 * @since 1.0
 */
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private UserDetailsService jwtUserServiceImpl;


    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.formLogin()
                .loginProcessingUrl("/login")
                .and()
                .authorizeRequests()
                // 允许对于网站静态资源的无授权访问
                .antMatchers(
                        HttpMethod.GET,
                        "/",
                        "/*.html",
                        "/favicon.ico",
                        "/**/*.html",
                        "/**/*.css",
                        "/**/*.js"
                ).permitAll()
//                .antMatchers("/image/**").permitAll() //静态资源访问无需认证
//                .antMatchers("/admin/**").hasAnyRole("ADMIN") //admin开头的请求，需要admin权限
//                .antMatchers("/article/**").hasRole("USER") //需登陆才能访问的url
//                .antMatchers("/get").permitAll()
                //默认其它的请求都需要认证，这里一定要添加
                .anyRequest().authenticated()
                .and()
                //CRSF禁用，因为不使用session
                .csrf().disable()
                //禁用session
                .sessionManagement().disable()
//                .formLogin().disable() //禁用form登录
                //支持跨域
                .cors()
                .and()
                //添加header设置，支持跨域和ajax请求
                .headers().addHeaderWriter(new StaticHeadersWriter(Arrays.asList(
                        new Header("Access-control-Allow-Origin", "*"),
                        new Header("Access-Control-Expose-Headers",
                                AuthorizationConstants.AUTHORIZATION))))
                .and() //拦截OPTIONS请求，直接返回header
                .addFilterAfter(new OptionsRequestFilter(), CorsFilter.class)
                //添加登录filter
                .apply(new UserLoginConfigurer<>()).setLoginSuccessHandlerAndReturn(userLoginSuccessHandler())
                .and()
                //添加token的filter .tokenValidSuccessHandler(jwtRefreshSuccessHandler())
                .apply(new JwtLoginConfigurer<>()).permissiveRequestUrls("/logout")
                .and()
                //使用默认的logoutFilter
                .logout()
//              .logoutUrl("/logout")   //默认就是"/logout"
                //logout时清除token
                .addLogoutHandler(tokenClearLogoutHandler())
                //logout成功后返回200
                .logoutSuccessHandler(new HttpStatusReturningLogoutSuccessHandler())
                .and()
                .sessionManagement().disable();
    }


    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(daoAuthenticationProvider()).authenticationProvider(jwtAuthenticationProvider());
    }

    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    protected AuthenticationProvider jwtAuthenticationProvider() {
        // "jwtAuthenticationProvider"
        return new JwtAuthenticationProvider(jwtUserService());
    }

    @Bean
    protected AuthenticationProvider daoAuthenticationProvider() throws Exception {
        // "daoAuthenticationProvider"
        //这里会默认使用BCryptPasswordEncoder比对加密后的密码，注意要跟createUser时保持一致
        DaoAuthenticationProvider daoProvider = new DaoAuthenticationProvider();
        daoProvider.setUserDetailsService(userDetailsService());
        return daoProvider;
    }


    @Override
    protected UserDetailsService userDetailsService() {
        return jwtUserServiceImpl;
    }

    @Bean("jwtUserService")
    protected JwtUserServiceImpl jwtUserService() {
        return (JwtUserServiceImpl) jwtUserServiceImpl;
    }

    @Bean
    protected UserLoginSuccessHandler userLoginSuccessHandler() {
        return new UserLoginSuccessHandler(jwtUserService());
    }

//    @Bean
//    protected JwtRefreshSuccessHandler jwtRefreshSuccessHandler() {
//        return new JwtRefreshSuccessHandler(jwtUserService());
//    }

    @Bean
    protected TokenClearLogoutHandler tokenClearLogoutHandler() {
        return new TokenClearLogoutHandler(jwtUserService());
    }

    @Bean
    protected CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("*"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "HEAD", "OPTION"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.addExposedHeader(AuthorizationConstants.AUTHORIZATION);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }


    @Autowired
    public void setJwtUserServiceImpl(UserDetailsService jwtUserServiceImpl) {
        this.jwtUserServiceImpl = jwtUserServiceImpl;
    }
}
