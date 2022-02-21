package org.example.jwt.security.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.JWTDecodeException;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;
import org.apache.commons.lang3.StringUtils;
import org.example.jwt.security.common.AuthorizationConstants;
import org.example.jwt.security.entity.JwtAuthenticationToken;
import org.jetbrains.annotations.NotNull;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestHeaderRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * <p> 请求中带token校验 <br>
 *
 * @author GuYongtao
 * @date 2022/1/13
 * @since 1.0
 */
@Getter(AccessLevel.PROTECTED)
@Setter()
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private RequestMatcher requiresAuthenticationRequestMatcher;

    private List<RequestMatcher> permissiveRequestMatchers;

    private AuthenticationManager authenticationManager;

    @NotNull
    private AuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();

    @NotNull
    private AuthenticationFailureHandler failureHandler = new SimpleUrlAuthenticationFailureHandler();


    public JwtAuthenticationFilter() {
        this.requiresAuthenticationRequestMatcher = new RequestHeaderRequestMatcher(
                AuthorizationConstants.AUTHORIZATION);
    }


    @Override
    protected void doFilterInternal(@NotNull HttpServletRequest request, @NotNull HttpServletResponse response,
                                    @NotNull FilterChain filterChain) throws ServletException, IOException {
        // TODO: 是否支持匿名访问？当前支持，没带token的放过（认证权限的时候也会进行校验）
        if (!requiresAuthentication(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        Authentication authenticationResult = null;
        AuthenticationException authenticationFailed = null;
        try {
            String token = getJwtToken(request);
            if (StringUtils.isNotBlank(token)) {
                JwtAuthenticationToken authToken = new JwtAuthenticationToken(JWT.decode(token));
                authenticationResult = this.getAuthenticationManager().authenticate(authToken);
            } else {
                authenticationFailed = new InsufficientAuthenticationException("JWT is empty.");
            }
        } catch (JWTDecodeException jwtDecodeException) {
            logger.error("JWT format error", jwtDecodeException);
            authenticationFailed = new InsufficientAuthenticationException("JWT format error", jwtDecodeException);
        } catch (InternalAuthenticationServiceException internalAuthenticationServiceException) {
            logger.error("认证用户时发生内部错误.", internalAuthenticationServiceException);
            authenticationFailed = internalAuthenticationServiceException;
        } catch (AuthenticationException authenticationException) {
            authenticationFailed = authenticationException;
        }

        if (Objects.nonNull(authenticationResult)) {
            logger.info("Authentication success: " + authenticationResult);
            successfulAuthentication(request, response, authenticationResult);
        } else if (!permissiveRequest(request)) {
            logger.error(authenticationFailed);
            unsuccessfulAuthentication(request, response, authenticationFailed);
            return;
        }

        filterChain.doFilter(request, response);
    }


    /**
     * <p> 返回请求中的token <br>
     *
     * @param request 请求
     * @return token
     */
    protected String getJwtToken(HttpServletRequest request) {
        String authInfo = request.getHeader("Authorization");
        return StringUtils.removeStart(authInfo, "Bearer ");
    }


    /**
     * <p> 判断请求是否带有token <br>
     *
     * @param request 请求
     * @return boolean
     */
    protected boolean requiresAuthentication(HttpServletRequest request) {
        return requiresAuthenticationRequestMatcher.matches(request);
    }


    /**
     * <p> 认证成功 <br>
     *
     * @param request    请求
     * @param response   响应
     * @param authResult 认证结果
     */
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            Authentication authResult)
            throws IOException, ServletException {
        SecurityContextHolder.getContext().setAuthentication(authResult);
//        getSimpleUrlAuthenticationSuccessHandler(request.getRequestURI()).onAuthenticationSuccess(request, response, authResult);
    }


    /**
     * <p> 判断请求在不在白名单中<br>
     *
     * @param request 请求
     * @return boolean
     */
    protected boolean permissiveRequest(HttpServletRequest request) {
        if (permissiveRequestMatchers == null) {
            return false;
        }
        for (RequestMatcher permissiveMatcher : permissiveRequestMatchers) {
            if (permissiveMatcher.matches(request)) {
                return true;
            }
        }
        return false;
    }


    /**
     * <p> 认证失败 <br>
     *
     * @param request  请求
     * @param response 响应
     * @param failed   失败原因
     */
    protected void unsuccessfulAuthentication(HttpServletRequest request,
                                              HttpServletResponse response, AuthenticationException failed)
            throws IOException, ServletException {
        SecurityContextHolder.clearContext();
        failureHandler.onAuthenticationFailure(request, response, failed);
    }


    /**
     * <p> 设置白名单url <br>
     *
     * @param urls 白名单urls
     */
    public void setPermissiveUrl(String... urls) {
        if (Objects.isNull(permissiveRequestMatchers)) {
            permissiveRequestMatchers = new ArrayList<>(16);
        }
        for (String url : urls) {
            permissiveRequestMatchers.add(new AntPathRequestMatcher(url));
        }
    }


    @Override
    public void afterPropertiesSet() {
        Assert.notNull(authenticationManager, "authenticationManager must be specified");
        Assert.notNull(successHandler, "AuthenticationSuccessHandler must be specified");
        Assert.notNull(failureHandler, "AuthenticationFailureHandler must be specified");
    }

}
