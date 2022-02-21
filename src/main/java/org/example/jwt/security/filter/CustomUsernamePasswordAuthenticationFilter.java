package org.example.jwt.security.filter;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.example.jwt.security.utils.UserHelper;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.StreamUtils;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * <p> 登陆请求filter <br>
 *
 * @author GuYongtao
 * @date 2022/1/13
 * @since 1.0
 */
public class CustomUsernamePasswordAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    public CustomUsernamePasswordAuthenticationFilter() {
        super(new AntPathRequestMatcher("/login", "POST"));
    }


    @Override
    public Authentication attemptAuthentication(HttpServletRequest httpServletRequest,
                                                HttpServletResponse httpServletResponse)
            throws AuthenticationException, IOException {
        String body = StreamUtils.copyToString(httpServletRequest.getInputStream(), StandardCharsets.UTF_8);
        String username = null;
        String password = null;
        if (StringUtils.hasText(body)) {
            JSONObject jsonObject = JSON.parseObject(body);
            username = jsonObject.getString("username");
            password = jsonObject.getString("password");
        }

        if (Objects.isNull(username)) {
            username = "";
        }
        if (Objects.isNull(password)) {
            password = "";
        }

        // 封装到token并提交
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(username.trim(), UserHelper.encodePassword(password));

        return this.getAuthenticationManager().authenticate(authenticationToken);
    }

}
