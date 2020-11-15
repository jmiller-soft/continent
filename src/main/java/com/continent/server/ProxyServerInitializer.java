/*
 * Copyright 2012 The Netty Project
 *
 * The Netty Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package com.continent.server;

import com.continent.handler.server.PortUnificationServerHandler;
import com.continent.random.RandomService;
import com.continent.service.HandshakeService;
import com.continent.service.SessionData;
import com.continent.service.SessionId;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.socket.SocketChannel;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;

public final class ProxyServerInitializer extends ChannelInitializer<SocketChannel> {
    
    private final RandomService randomService;
    private final Map<SessionId, SessionData> sessions;
    private final Set<String> whiteListedHosts;
    private final ExecutorService executorService;
    private final Map<byte[], byte[]> id2PubKey;
    private final boolean tcpNodelay;
    private final int delayInMillis;
    private final boolean useRandomPackets;
    
    public ProxyServerInitializer(RandomService randomService, Map<SessionId, SessionData> sessions, Set<String> whiteListedHosts,
            ExecutorService executorService, Map<byte[], byte[]> id2PubKey, boolean tcpNodelay, int delayInMillis, boolean useRandomPackets) {
        this.randomService = randomService;
        this.sessions = sessions;
        this.whiteListedHosts = whiteListedHosts;
        this.executorService = executorService;
        this.id2PubKey = id2PubKey;
        this.tcpNodelay = tcpNodelay;
        this.delayInMillis = delayInMillis;
        this.useRandomPackets = useRandomPackets;
    }

    @Override
    public void initChannel(SocketChannel ch) throws Exception {
        HandshakeService handshakeService = new HandshakeService(executorService, randomService, sessions, id2PubKey);
        ch.pipeline().addLast(new PortUnificationServerHandler(handshakeService, randomService, delayInMillis, whiteListedHosts, tcpNodelay, useRandomPackets));
    }
}
