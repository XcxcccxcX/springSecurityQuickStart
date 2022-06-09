package com.chang.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import javax.servlet.Filter;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

/**
 * @Description securityConfig
 * @Author wind
 * @Date 2022/6/8
 **/
@Configuration
public class SecurityConfig {

    /**
     * There is no PasswordEncoder mapped for the id "null"
     * @return
     */
    @Bean
    public PasswordEncoder passwordEncoder(){
        return NoOpPasswordEncoder.getInstance();
    }

    /**
     * 实际开发中 用户都是存储再数据库     需实现 UserDetails
     * @return
     */
    @Bean
    public UserDetailsService userDetailsService(){
        InMemoryUserDetailsManager memoryUserDetails = new InMemoryUserDetailsManager();
        memoryUserDetails.createUser(User.withUsername("hsu").password("hsu").roles("admin").build());
        memoryUserDetails.createUser(User.withUsername("chang").password("chang").roles("user").build());
        return memoryUserDetails;
    }

    @Bean
    WebSecurityCustomizer webSecurityCustomizer(){
        return web -> web.ignoring().antMatchers("/js/**", "/css/**", "/images/**");
    }

    @Bean
    RoleHierarchy roleHierarchy(){
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        roleHierarchy.setHierarchy("ROLE_admin > ROLE_user");
        return roleHierarchy;
    }


    @Bean
    SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
//        httpSecurity
//                .antMatcher("/**")
//                .authorizeRequests(authorize -> authorize
//                        .anyRequest().authenticated())
//                .formLogin(a -> a.loginPage("/login.html"))
//                        .csrf(AbstractHttpConfigurer::disable);
//        return httpSecurity.build();

        httpSecurity
                .authorizeRequests()
                .antMatchers("/admin/*").hasRole("admin")
                .antMatchers("/user/*").hasRole("user")
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .loginPage("/login.html")

                // 登录参数的定义。
                .loginProcessingUrl("/doLogin")
                .usernameParameter("username")
                .passwordParameter("password")

                // 登录成功回调
                .successHandler((request, response, authentication) -> {
                    response.setContentType("application/json;charset=utf-8");
                    PrintWriter writer = response.getWriter();
                    writer.write(new ObjectMapper().writeValueAsString(authentication.getPrincipal()));
                    writer.flush();
                    writer.close();
                })

                //登录失败回调
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                        response.setContentType("application/json;charset=utf-8");
                        PrintWriter writer = response.getWriter();
                        writer.write(new ObjectMapper().writeValueAsString(exception.getMessage()));
                        writer.flush();
                        writer.close();
                    }
                })


                // 登录成功后跳转
                // 服务端跳转
                // 登录成功后的跳转地址 固定跳转到该地址
//                .successForwardUrl("/index")

                // 客户端跳转 重定向
                // defaultSuccessUrl 有一个重载方式 alwaysUse = true 效果和successForwardUrl一样
//                .defaultSuccessUrl("/index")

                // 登录失败后跳转
                // 服务端跳转
//                .failureForwardUrl("/fail")
                // 重定向
//                .failureUrl("/fail")
                .permitAll()
                .and()
                .logout()
                // 指定退出登录的地址 和 请求方式
//                .logoutUrl("/logout")
//                .logoutRequestMatcher(new AntPathRequestMatcher("/logout","POST"))
                // 退出登录后 跳转到登录页面
                .logoutSuccessUrl("/logout")
                // 退出登录成功后的回调
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        response.setContentType("application/json;charset=utf-8");
                        PrintWriter writer = response.getWriter();
                        writer.write(new ObjectMapper().writeValueAsString("退出成功!"));
                        writer.flush();
                        writer.close();
                    }
                })

                // 默认也是true

                // 是否让session失效
//                .invalidateHttpSession(true)
                // 清除认证信息
//                .clearAuthentication(true)
                .permitAll()
                .and()
                .csrf().disable()

                // 未认证处理方案
                .exceptionHandling()
                .authenticationEntryPoint(new AuthenticationEntryPoint() {
                    @Override
                    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
                        response.setContentType("application/json;charset=utf-8");
                        PrintWriter writer = response.getWriter();
                        writer.write(new ObjectMapper().writeValueAsString("尚未登录, 请先登录!"));
                        writer.flush();
                        writer.close();
                    }
                });
        return httpSecurity.build();
    }


}
