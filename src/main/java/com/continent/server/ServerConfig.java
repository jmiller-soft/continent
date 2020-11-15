package com.continent.server;

import java.util.Collection;
import java.util.Collections;
import java.util.Set;

public class ServerConfig {

    int port;
    Set<String> whiteListedHosts = Collections.emptySet();
    boolean tcpNoDelay;
    int maxWriteDelayMs;
    boolean useRandomPackets;
    Collection<String> keys;
    int nonceSeedInterval;
    int keySeedInterval;
    long sessionTimeout;

    public long getSessionTimeout() {
        return sessionTimeout;
    }
    public void setSessionTimeout(long sessionTimeout) {
        this.sessionTimeout = sessionTimeout;
    }

    public int getNonceSeedInterval() {
        return nonceSeedInterval;
    }
    public void setNonceSeedInterval(int nonceSeedInterval) {
        this.nonceSeedInterval = nonceSeedInterval;
    }

    public Integer getKeySeedInterval() {
        return keySeedInterval;
    }
    public void setKeySeedInterval(Integer keySeedInterval) {
        this.keySeedInterval = keySeedInterval;
    }

    public void setPort(int port) {
        this.port = port;
    }
    public void setWhiteListedHosts(Set<String> whiteListedHosts) {
        this.whiteListedHosts = whiteListedHosts;
    }
    public void setTcpNoDelay(boolean tcpNoDelay) {
        this.tcpNoDelay = tcpNoDelay;
    }
    public void setMaxWriteDelayMs(int maxWriteDelayMs) {
        this.maxWriteDelayMs = maxWriteDelayMs;
    }
    public void setUseRandomPackets(boolean useRandomPackets) {
        this.useRandomPackets = useRandomPackets;
    }
    public void setKeys(Collection<String> keys) {
        this.keys = keys;
    }
    public int getPort() {
        return port;
    }
    public Set<String> getWhiteListedHosts() {
        return whiteListedHosts;
    }
    public boolean isTcpNoDelay() {
        return tcpNoDelay;
    }
    public int getMaxWriteDelayMs() {
        return maxWriteDelayMs;
    }
    public boolean isUseRandomPackets() {
        return useRandomPackets;
    }
    public Collection<String> getKeys() {
        return keys;
    }
    
    
    
}
