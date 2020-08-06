package com.example.mixedauth;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping
public class WebController {

    @GetMapping
    public String hello() {
        return "views/hello";
    }

}
