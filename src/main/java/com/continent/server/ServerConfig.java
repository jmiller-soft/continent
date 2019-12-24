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
