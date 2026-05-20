package com.jwt.authentication.integration;


import com.jwt.authentication.payload.response.TokenResponse;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.*;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class MenuControllerIT {

    @Autowired
    private TestRestTemplate restTemplate;

    //TEST CASE 1 : authen + request menu list + existing IT User (USER,ADMIN) :success
    @Test
    void getMenus_RoleIT_shouldReturnList() {
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
        headers.setBearerAuth(token);
        HttpEntity<Void> request = new HttpEntity<>(headers);

        ResponseEntity<String> response =
                restTemplate.exchange(
                        "/permissions/get-permissions",
                        HttpMethod.GET,
                        request,
                        String.class
                );

        // 3. check status
        assertEquals(200, response.getStatusCode().value());

        // 4. check body
        assertNotNull(response.getBody());

        // 5. basic validation (กัน empty response)
        assertTrue(response.getBody().startsWith("[") || response.getBody().contains("permissions"));


    }
}