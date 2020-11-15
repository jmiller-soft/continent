package com.continent.service;

import org.bouncycastle.crypto.prng.RandomGenerator;

import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;

public class SessionData {

    private final byte[] clientKey;
    private final byte[] serverKey;
    private final List<Object> clientCiphers;
    private final List<Object> serverCiphers;
    private final byte[] randomTimeouts;
    private final ReentrantLock lock;
    private byte[] ivData;

    private RandomGenerator clientSessionGenerator;
    private RandomGenerator serverSessionGenerator;
    private RandomGenerator clientIVGenerator;
    private RandomGenerator serverIVGenerator;

    private final AtomicInteger usage;
    private volatile long lastAccessTime = System.currentTimeMillis();
    
    public SessionData(byte[] clientKey, byte[] serverKey,
            List<Object> clientCiphers, List<Object> serverCiphers,
            byte[] randomTimeouts) {
        super();
        this.clientKey = clientKey;
        this.serverKey = serverKey;
        this.clientCiphers = clientCiphers;
        this.serverCiphers = serverCiphers;
        this.randomTimeouts = randomTimeouts;
        this.lock = new ReentrantLock();
        this.usage = new AtomicInteger();
    }

    public SessionData(SessionData data, byte[] iv) {
        this.clientKey = data.clientKey;
        this.serverKey = data.serverKey;
        this.clientCiphers = data.clientCiphers;
        this.serverCiphers = data.serverCiphers;
        this.randomTimeouts = data.randomTimeouts;
        this.clientSessionGenerator = data.clientSessionGenerator;
        this.serverSessionGenerator = data.serverSessionGenerator;
        this.clientIVGenerator = data.clientIVGenerator;
        this.serverIVGenerator = data.serverIVGenerator;
        this.ivData = iv;
        this.usage = data.usage;
        this.lock = data.lock;
    }

    public ReentrantLock getLock() {
        return lock;
    }

    public byte[] getIvData() {
        return ivData;
    }

    public RandomGenerator getClientSessionGenerator() {
        return clientSessionGenerator;
    }

    public void setClientSessionGenerator(RandomGenerator clientSessionGenerator) {
        this.clientSessionGenerator = clientSessionGenerator;
    }

    public RandomGenerator getServerSessionGenerator() {
        return serverSessionGenerator;
    }

    public void setServerSessionGenerator(RandomGenerator serverSessionGenerator) {
        this.serverSessionGenerator = serverSessionGenerator;
    }

    public RandomGenerator getClientIVGenerator() {
        return clientIVGenerator;
    }

    public void setClientIVGenerator(RandomGenerator clientIVGenerator) {
        this.clientIVGenerator = clientIVGenerator;
    }

    public RandomGenerator getServerIVGenerator() {
        return serverIVGenerator;
    }

    public void setServerIVGenerator(RandomGenerator serverIVGenerator) {
        this.serverIVGenerator = serverIVGenerator;
    }

    public void clear() {
        serverCiphers.clear();
        clientCiphers.clear();
        Arrays.fill(clientKey, (byte)0);
        Arrays.fill(serverKey, (byte)0);
    }
    
    public byte[] getRandomTimeouts() {
        return randomTimeouts;
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
