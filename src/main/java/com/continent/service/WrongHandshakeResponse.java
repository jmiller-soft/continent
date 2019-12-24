package com.continent.service;

public class WrongHandshakeResponse extends RuntimeException {

    public WrongHandshakeResponse(String message) {
        super(message);
    }
}
