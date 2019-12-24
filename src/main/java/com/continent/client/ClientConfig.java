package com.continent.client;

import java.util.List;
import java.util.Map;

public class ClientConfig {

    List<String> servers;
    Integer port;
    String keyRotationInterval;
    boolean tcpNoDelay;
    boolean useRandomPackets;
    String key;
    Integer maxWriteDelayMs;
    Map<Integer, String> portMapping;
    
    public List<String> getServers() {
        return servers;
    }
    public void setServers(List<String> servers) {
        this.servers = servers;
    }
    public Integer getPort() {
        return port;
    }
    public void setPort(Integer port) {
        this.port = port;
    }
    public String getKeyRotationInterval() {
        return keyRotationInterval;
    }
    public void setKeyRotationInterval(String keyRotationInterval) {
        this.keyRotationInterval = keyRotationInterval;
    }
    public boolean isTcpNoDelay() {
        return tcpNoDelay;
    }
    public void setTcpNoDelay(boolean tcpNoDelay) {
        this.tcpNoDelay = tcpNoDelay;
    }
    public boolean isUseRandomPackets() {
        return useRandomPackets;
    }
    public void setUseRandomPackets(boolean useRandomPackets) {
        this.useRandomPackets = useRandomPackets;
    }
    public String getKey() {
        return key;
    }
    public void setKey(String key) {
        this.key = key;
    }
    public Integer getMaxWriteDelayMs() {
        return maxWriteDelayMs;
    }
    public void setMaxWriteDelayMs(Integer maxWriteDelayMs) {
        this.maxWriteDelayMs = maxWriteDelayMs;
    }
    public Map<Integer, String> getPortMapping() {
        return portMapping;
    }
    public void setPortMapping(Map<Integer, String> portMapping) {
        this.portMapping = portMapping;
    }

    
}
