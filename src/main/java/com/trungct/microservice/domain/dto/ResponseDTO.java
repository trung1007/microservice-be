package com.trungct.microservice.domain.dto;

import lombok.Data;

@Data
public class ResponseDTO<T> {
    private int statusCode;
    private String error;

    private Object message;

    private String accessToken;


    private T  data;

}
