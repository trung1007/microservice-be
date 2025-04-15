package com.trungct.microservice.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.trungct.microservice.domain.dto.ResponseDTO;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class CustomEntryPoint implements AuthenticationEntryPoint {
    private final ObjectMapper objectMapper = new ObjectMapper();
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        ResponseDTO<Object> responseDTO = new ResponseDTO<>();
        responseDTO.setStatusCode(HttpServletResponse.SC_UNAUTHORIZED); // 401
        responseDTO.setError("Unauthorized");
        responseDTO.setMessage("Token không hợp lệ");
        responseDTO.setData(null);

        response.setContentType("application/json; charset=UTF-8");
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.getWriter().write(objectMapper.writeValueAsString(responseDTO));
    }
}
