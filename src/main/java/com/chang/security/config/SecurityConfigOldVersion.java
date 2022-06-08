package com.chang.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.Filter;
import java.util.ArrayList;
import java.util.List;

/**
 * @Description securityConfig
 * @Author wind
 * @Date 2022/6/8
 **/
//@Configuration
public class SecurityConfigOldVersion extends WebSecurityConfigurerAdapter {

    /**
     * There is no PasswordEncoder mapped for the id "null"
     * @return
     */
    @Bean
    public PasswordEncoder passwordEncoder(){
        return NoOpPasswordEncoder.getInstance();
    }

    /**
     * 用户信息
     * @param auth
     * @throws Exception
     *
     * configure 方法中，我们通过 inMemoryAuthentication 来开启在内存中定义用户，withUser 中是用户名，password 中则是用户密码，roles 中是用户角色。
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("oldUser")
                .password("oldUser")
                .roles("admin");
    }

    /**
     * 忽略的资源 或者方法路径
     * 用来配置忽略掉的 URL 地址，一般对于静态文件，我们可以采用此操作。
     * @param web
     */
    @Override
    public void configure(WebSecurity web) {
        web.ignoring().antMatchers("/js/**", "/css/**", "/images/**")
//                .antMatchers("/hello")
        ;
    }

    /**
     * 如果我们使用 XML 来配置 Spring Security ，里边会有一个重要的标签 <http>，HttpSecurity 提供的配置方法 都对应了该标签。
     * authorizeRequests 对应了 <intercept-url>。
     * formLogin 对应了 <formlogin>。
     * and 方法表示结束当前标签，上下文回到HttpSecurity，开启新一轮的配置。
     * permitAll 表示登录相关的页面/接口不要被拦截。
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .loginPage("/login.html")
                .permitAll()
                .and()
                .csrf().disable();
    }
}
