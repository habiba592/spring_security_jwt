package com.spring.evmp.exception;

public class ForbiddenUserException extends RuntimeException {
    public ForbiddenUserException(String message) {
        super(message);
    }
}