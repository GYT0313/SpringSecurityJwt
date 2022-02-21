package org.example.jwt.security.entity;

import lombok.*;

import java.io.Serializable;

/**
 * <p> redis存储实体 </br>
 *
 * @author GuYongtao
 * @date 2022/1/16
 * @since 1.0
 */
@Getter
@Setter
@ToString
@AllArgsConstructor
@NoArgsConstructor
public class RedisInfo implements Serializable {

    private static final long serialVersionUID = -3780948238584554424L;

    private Integer id;

    private String passwordSalt;

    private String token;

}
