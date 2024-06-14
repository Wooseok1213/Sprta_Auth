package com.sparta.springauth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration //Bean을 등록하는 메서드가 속한 해당 클래스에 @Configuration을 설정합니다.
public class PasswordConfig {

    @Bean
//    Bean으로 등록하고자하는 객체를 반환하는 메서드를 선언하고 @Bean을 설정합니다.

    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(); //BCrypt = Hash 함수 비밀번호를 암호화해주는 Hash함수

    }
}
