package com.continent.service;

import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicInteger;

import io.netty.util.internal.PlatformDependent;

public class SessionData {

    private final byte[] sessionId;
    private final byte[] clientKey;
    private final byte[] serverKey;
    private final List<Object> clientCiphers;
    private final List<Object> serverCiphers;
    private final byte[] randomTimeouts;
    
    private final AtomicInteger usage = new AtomicInteger();
    private volatile long lastAccessTime = System.currentTimeMillis();
    
    private final ConcurrentMap<Long, Boolean> authentificatedMacs = PlatformDependent.newConcurrentHashMap();
    
    public SessionData(byte[] clientKey, byte[] serverKey, 
            List<Object> clientCiphers, List<Object> serverCiphers, byte[] sessionId,
            byte[] randomTimeouts) {
        super();
        this.clientKey = clientKey;
        this.serverKey = serverKey;
        this.clientCiphers = clientCiphers;
        this.serverCiphers = serverCiphers;
        this.sessionId = sessionId;
        this.randomTimeouts = randomTimeouts;
    }

    public void clear() {
        serverCiphers.clear();
        clientCiphers.clear();
        Arrays.fill(sessionId, (byte)0);
        Arrays.fill(clientKey, (byte)0);
        Arrays.fill(serverKey, (byte)0);
    }
    
    public byte[] getRandomTimeouts() {
        return randomTimeouts;
    }
    
    public boolean addSessionMac(Long mac) {
        return authentificatedMacs.putIfAbsent(mac, Boolean.TRUE) == null;
    }
    
    public int countSessionsMacs() {
        return authentificatedMacs.size();
    }
    
    public byte[] getSessionId() {
        return sessionId;
    }
    
    public void incUsage() {
        usage.incrementAndGet();
    }
    
    public void decUsage() {
        usage.decrementAndGet();
    }
    
    public int getUsage() {
        return usage.get();
    }
    
    public void updateLastAccessTime() {
        lastAccessTime = System.currentTimeMillis();
    }
    
    public long getLastAccessTime() {
        return lastAccessTime;
    }
    
    public List<Object> getClientCiphers() {
        return clientCiphers;
    }
    
    public byte[] getClientKey() {
        return clientKey;
    }
    
    public List<Object> getServerCiphers() {
        return serverCiphers;
    }
    
    public byte[] getServerKey() {
        return serverKey;
    }

}
