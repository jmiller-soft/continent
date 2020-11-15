package com.continent.service;

import java.util.Arrays;

public class SessionId {

    public static final int SIZE = 16;

    private byte[] sessionId;

    public SessionId(byte[] sessionId) {
        this.sessionId = sessionId;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SessionId sessionId1 = (SessionId) o;
        return Arrays.equals(sessionId, sessionId1.sessionId);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(sessionId);
    }
}
