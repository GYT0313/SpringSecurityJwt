//package org.example.jwt.security;
//
//import com.auth0.jwt.interfaces.DecodedJWT;
//import org.example.security.common.AuthorizationConstants;
//import org.example.security.service.JwtUserServiceImpl;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
//
//import javax.servlet.ServletException;
//import javax.servlet.http.HttpServletRequest;
//import javax.servlet.http.HttpServletResponse;
//import java.io.IOException;
//import java.time.LocalDateTime;
//import java.time.ZoneId;
//import java.util.Date;
//
//
///**
// * <p> 认证成功后刷新token <br>
// *
// * @author GuYongtao
// * @date 2022/1/13
// * @since 1.0
// */
//public class JwtRefreshSuccessHandler implements AuthenticationSuccessHandler {
//
//    // 30s
//    private static final int TOKEN_REFRESH_INTERVAL = 30;
//
//    private final JwtUserServiceImpl jwtUserServiceImpl;
//
//    public JwtRefreshSuccessHandler(JwtUserServiceImpl jwtUserServiceImpl) {
//        this.jwtUserServiceImpl = jwtUserServiceImpl;
//    }
//
//
//    @Override
//    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
//                                        Authentication authentication) throws IOException, ServletException {
//        DecodedJWT jwt = ((JwtAuthenticationToken) authentication).getToken();
//        boolean shouldRefresh = shouldTokenRefresh(jwt.getIssuedAt());
//        if (shouldRefresh) {
//            String newToken = jwtUserServiceImpl.saveUserLoginInfo((UserDetails) authentication.getPrincipal());
//            response.setHeader(AuthorizationConstants.AUTHORIZATION, newToken);
//        }
//    }
//
//
//    /**
//     * <p> 根据time判断是否刷新token <br>
//     *
//     * @param issueAt 请求token中的time
//     * @return boolean
//     */
//    protected boolean shouldTokenRefresh(Date issueAt) {
//        LocalDateTime issueTime = LocalDateTime.ofInstant(issueAt.toInstant(), ZoneId.systemDefault());
//        return LocalDateTime.now().minusSeconds(TOKEN_REFRESH_INTERVAL).isAfter(issueTime);
//    }
//}
