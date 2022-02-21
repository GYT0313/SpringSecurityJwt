package org.example.jwt.security.handler;

import org.example.jwt.security.service.JwtUserServiceImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 * <p> logout token处理 <br>
 *
 * @author GuYongtao
 * @date 2022/1/13
 * @since 1.0
 */
public class TokenClearLogoutHandler implements LogoutHandler {

    private final JwtUserServiceImpl jwtUserServiceImpl;

    public TokenClearLogoutHandler(JwtUserServiceImpl jwtUserServiceImpl) {
        this.jwtUserServiceImpl = jwtUserServiceImpl;
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        if (authentication == null) {
            return;
        }
        UserDetails user = (UserDetails) authentication.getPrincipal();
        if (user != null && user.getUsername() != null) {
            jwtUserServiceImpl.deleteUserLoginInfo(user.getUsername());
        }
    }

}
