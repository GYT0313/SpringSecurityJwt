package org.example.jwt.security.utils;

import sun.misc.BASE64Encoder;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * <p> 用户信息操作帮助类 </br>
 *
 * @author GuYongtao
 * @date 2022/1/16
 * @since 1.0
 */
public class UserHelper {

    private static MessageDigest md5;

    private static BASE64Encoder base64en;

    static {
        try {
            md5 = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        base64en = new BASE64Encoder();
    }


    /**
     * <p> 默认md5加密密码 </br>
     *
     * @param password 密码
     * @return 加密后的密码
     */
    public static String encodePassword(String password) {
        return base64en.encode(md5.digest(password.getBytes(StandardCharsets.UTF_8)));
    }


    /**
     * <p> 验证密码是否正确 </br>
     *
     * @param password       用户输入密码
     * @param encodePassword 数据库密码
     * @return boolean
     */
    public boolean checkPassword(String password, String encodePassword) {
        return encodePassword(password).equals(encodePassword);
    }
}
