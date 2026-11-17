
package com.example.demo.controller;

import com.example.demo.service.JwtService;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class JwtController {

    private final JwtService jwtService;

    public JwtController(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    // Generate JWT token
    @PostMapping("/generate")
    public ResponseEntity<?> generateToken(
            @RequestParam String username,
            @RequestParam String role) {

        String token = jwtService.generateToken(username, role);

        Map<String, Object> response = new HashMap<>();

        response.put("token", token);
        response.put("message", "JWT generated successfully");

        return ResponseEntity.ok(response);
    }

    // Validate JWT token and extract claims
    @GetMapping("/validate")
    public ResponseEntity<?> validateToken(
            @RequestHeader(
                value = "Authorization",
                required = false
            ) String authHeader) {

        if (authHeader == null ||
                !authHeader.startsWith("Bearer ")) {

            return ResponseEntity.badRequest()
                    .body("Missing Bearer token");
        }

        String token = authHeader.substring(7);

        try {

            Claims claims = jwtService.validateToken(token);

            Map<String, Object> response = new HashMap<>();

            response.put("valid", true);
            response.put("username", claims.getSubject());
            response.put("role", claims.get("role"));
            response.put("issuedAt", claims.getIssuedAt());
            response.put("expiration", claims.getExpiration());

            return ResponseEntity.ok(response);

        } catch (ExpiredJwtException e) {

            return ResponseEntity.status(401)
                    .body("JWT Token has expired");

        } catch (JwtException | IllegalArgumentException e) {

            return ResponseEntity.status(401)
                    .body("Invalid JWT Token");
        }
    }
}
