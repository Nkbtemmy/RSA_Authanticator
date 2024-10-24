package com.imanzi.rsa_authanticator.utils.exception;


import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UserException extends RuntimeException {
    private final String errorCode;
    private final String errorMessage;

    public UserException(String errorCode, String errorMessage) {
        super(errorMessage);
        this.errorCode = errorCode;
        this.errorMessage = errorMessage;
    }

}
