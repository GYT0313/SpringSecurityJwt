package org.example.jwt.security.handler;

import org.example.jwt.security.service.JwtUserServiceImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * <p> 用户登陆成功处理 <br>
 *
 * @author GuYongtao
 * @date 2022/1/13
 * @since 1.0
 */
public class UserLoginSuccessHandler implements AuthenticationSuccessHandler {

    private final JwtUserServiceImpl jwtUserServiceImpl;

    public UserLoginSuccessHandler(JwtUserServiceImpl jwtUserServiceImpl) {
        this.jwtUserServiceImpl = jwtUserServiceImpl;
    }


    /**
     * Called when a user has been successfully authenticated.
     *
     * @param request        the request which caused the successful authentication
     * @param response       the response
     * @param authentication the <tt>Authentication</tt> object which was created during
     */
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) {
        UserDetails principal = (UserDetails) authentication.getPrincipal();
        String token = jwtUserServiceImpl.saveUserLoginInfo(principal);
        response.setHeader("Authorization", token);
    }
}
