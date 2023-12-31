package com.example.security.controller;


import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@Validated
@RestController
public class SecurityController {

  @GetMapping("/")
  public String index() {
    return "home";
  }

  @GetMapping("/loginPage")
  public String loginPage() {
    return "loginPage";
  }

}
