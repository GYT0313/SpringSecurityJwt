package org.example.jwt.security.entity;

import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.Getter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;

/**
 * <p> jtw token <br>
 *
 * @author GuYongtao
 * @date 2022/1/13
 * @since 1.0
 */
@Getter
public class JwtAuthenticationToken extends AbstractAuthenticationToken {

    private UserDetails principal;

    private String credentials;

    private final DecodedJWT decodedJWT;


    public JwtAuthenticationToken(DecodedJWT decodedJWT) {
        super(Collections.emptyList());
        this.decodedJWT = decodedJWT;
    }


    public JwtAuthenticationToken(UserDetails principal, DecodedJWT decodedJWT,
                                  Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        this.decodedJWT = decodedJWT;
    }


    @Override
    public void setDetails(Object details) {
        super.setDetails(details);
        this.setAuthenticated(true);
    }

}
