package com.chang.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
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
import javax.sql.DataSource;

import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
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

    @Autowired
    DataSource dataSource;

    /**
     * ??????????????? ??????????????????????????????     ????????? UserDetails
     * @return
     */
    @Bean
    public UserDetailsService userDetailsService(){
        // ??????InMemoryUserDetailsManager ???????????????????????? JdbcUserDetailsManager ?????????
        JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager();
        // ???????????????
        jdbcUserDetailsManager.setDataSource(dataSource);
        if (!jdbcUserDetailsManager.userExists("hsu")) {
            jdbcUserDetailsManager.createUser(User.withUsername("hsu").password("hsu").roles("admin").build());
        }
        if (!jdbcUserDetailsManager.userExists("chang")) {
            jdbcUserDetailsManager.createUser(User.withUsername("chang").password("chang").roles("user").build());
        }
        return jdbcUserDetailsManager;
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

                // ????????????????????????
                .loginProcessingUrl("/doLogin")
                .usernameParameter("username")
                .passwordParameter("password")

                // ??????????????????
                .successHandler((request, response, authentication) -> {
                    response.setContentType("application/json;charset=utf-8");
                    PrintWriter writer = response.getWriter();
                    writer.write(new ObjectMapper().writeValueAsString(authentication.getPrincipal()));
                    writer.flush();
                    writer.close();
                })

                //??????????????????
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


                // ?????????????????????
                // ???????????????
                // ?????????????????????????????? ????????????????????????
//                .successForwardUrl("/index")

                // ??????????????? ?????????
                // defaultSuccessUrl ????????????????????? alwaysUse = true ?????????successForwardUrl??????
//                .defaultSuccessUrl("/index")

                // ?????????????????????
                // ???????????????
//                .failureForwardUrl("/fail")
                // ?????????
//                .failureUrl("/fail")
                .permitAll()
                .and()
                .logout()
                // ??????????????????????????? ??? ????????????
//                .logoutUrl("/logout")
//                .logoutRequestMatcher(new AntPathRequestMatcher("/logout","POST"))
                // ??????????????? ?????????????????????
                .logoutSuccessUrl("/logout")
                // ??????????????????????????????
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        response.setContentType("application/json;charset=utf-8");
                        PrintWriter writer = response.getWriter();
                        writer.write(new ObjectMapper().writeValueAsString("????????????!"));
                        writer.flush();
                        writer.close();
                    }
                })

                // ????????????true

                // ?????????session??????
//                .invalidateHttpSession(true)
                // ??????????????????
//                .clearAuthentication(true)
                .permitAll()
                .and()
                .csrf().disable()

                // ?????????????????????
                .exceptionHandling()
                .authenticationEntryPoint(new AuthenticationEntryPoint() {
                    @Override
                    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
                        response.setContentType("application/json;charset=utf-8");
                        PrintWriter writer = response.getWriter();
                        writer.write(new ObjectMapper().writeValueAsString("????????????, ????????????!"));
                        writer.flush();
                        writer.close();
                    }
                });
        return httpSecurity.build();
    }


}
