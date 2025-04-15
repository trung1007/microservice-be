package com.trungct.microservice.utils;

import com.trungct.microservice.domain.dto.ResponseDTO;
import org.springframework.core.MethodParameter;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;

@ControllerAdvice
public class FormatResponse implements ResponseBodyAdvice<Object> {
    @Override
    public boolean supports(MethodParameter returnType, Class<? extends HttpMessageConverter<?>> converterType) {
        return true;
    }

    @Override
    public Object beforeBodyWrite(
            Object body,
            MethodParameter returnType,
            MediaType selectedContentType,
            Class<? extends HttpMessageConverter<?>> selectedConverterType,
            ServerHttpRequest request,
            ServerHttpResponse response
    ) {
        int status = 200; // default
        if (response instanceof ServletServerHttpResponse servletResponse) {
            status = servletResponse.getServletResponse().getStatus();
        }

        if (body instanceof ResponseDTO || body instanceof String) {
            return body;
        }

        ResponseDTO<Object> responseDTO = new ResponseDTO<>();

        responseDTO.setStatusCode(status);

        if (status >= 400) {
            responseDTO.setError("Call API failed");
            responseDTO.setMessage(body);
        } else {
            responseDTO.setData(body);
            responseDTO.setMessage("Call API success");
        }

        return responseDTO;
    }
}
