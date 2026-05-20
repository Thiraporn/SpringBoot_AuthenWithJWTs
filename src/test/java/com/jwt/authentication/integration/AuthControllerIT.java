package com.jwt.authentication.integration;


import com.jwt.authentication.payload.response.TokenResponse;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;

import static org.junit.jupiter.api.Assertions.*;
//ใช้ SpringBootTest ยิง API
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class AuthControllerIT {

    @Autowired
    private TestRestTemplate restTemplate;
    //TEST CASE 1 : register success
    @Test
    void register_shouldReturn200() {

        String requestBody = """
        {
            "user": "springbootit",
            "pwd": "012347890"
        }
        """;

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        HttpEntity<String> request = new HttpEntity<>(requestBody, headers);

        ResponseEntity<String> response = restTemplate.postForEntity(
                "/register",
                request,
                String.class
        );

        assertEquals(200, response.getStatusCode().value());
    }
    //TEST CASE 2 : authen user success
    @Test
    void login_shouldReturnToken() {
        String requestBody = """
        {
            "user": "springbootuser",
            "pwd": "012347890"
        }
        """;
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<String> request = new HttpEntity<>(requestBody, headers);

        ResponseEntity<String> response = restTemplate.postForEntity(
                "/authen",
                request,
                String.class
        );

        assertEquals(200, response.getStatusCode().value());
        assertTrue(response.getBody().contains("token"));


    }
    //TEST CASE 3 : authen IT success + resquest user data
    @Test
    void getUsers_shouldWorkWithToken() {

        // 1. login
        String loginBody = """
        {
            "user": "springbootit",
            "pwd": "012347890"
        }
        """;
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<String> requestLogin = new HttpEntity<>(loginBody, headers);

        ResponseEntity<TokenResponse> loginResponse = restTemplate.postForEntity(
                "/authen",
                requestLogin,
                TokenResponse.class
        );

        String token = loginResponse.getBody().getAccessToken();

        // 2. call secured API
        //HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);

        HttpEntity<Void> request = new HttpEntity<>(headers);

        ResponseEntity<String> response = restTemplate.exchange(
                "/users/all-users",
                HttpMethod.POST,
                request,
                String.class
        );

        assertEquals(200, response.getStatusCode().value());
    }
}