package com.chang.security.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @Description login
 * @Author wind
 * @Date 2022/6/8
 **/
@RestController
public class LoginController {

    @GetMapping("/hello")
    public String login(){
        return "success";
    }

    @GetMapping("/cc")
    public String cc(){
        return "cc";
    }

    @RequestMapping("/index")
    public String index(){
        return "index";
    }

    @RequestMapping("/fail")
    public String fail(){
        return "fail";
    }

    @RequestMapping("/admin/hello")
    public String adminHello(){
        return "admin";
    }

    @RequestMapping("/user/hello")
    public String userHello(){
        return "user";
    }
}
