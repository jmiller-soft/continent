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
package com.continent.client;

import java.net.URI;
import java.util.List;

import com.continent.random.RandomService;
import com.continent.service.HandshakeService;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.group.ChannelGroup;
import io.netty.channel.socket.SocketChannel;

public class ProxyClientInitializer extends ChannelInitializer<SocketChannel> {

    private final RandomService randomService;
    private final HandshakeService handshakeService;
    private final String mappedHost;
    private final boolean tcpNodelay;
    private final List<URI> urls;
    private final ChannelGroup group;
    private final Integer delayInMillis;
    private final boolean useRandomPackets;

    public ProxyClientInitializer(List<URI> urls, RandomService randomService, HandshakeService handshakeService, 
            String mappedHost, boolean tcpNodelay, ChannelGroup group, Integer delayInMillis, boolean useRandomPackets) {
        this.urls = urls;
        this.randomService = randomService;
        this.mappedHost = mappedHost;
        this.handshakeService = handshakeService;
        this.tcpNodelay = tcpNodelay;
        this.group = group;
        this.delayInMillis = delayInMillis;
        this.useRandomPackets = useRandomPackets;
    }

    @Override
    public void initChannel(SocketChannel ch) {
        ch.pipeline().addLast(
//                new LoggingHandler("frontend", LogLevel.INFO),
                new ProxyClientHandler(urls, randomService, 
                        handshakeService, mappedHost, tcpNodelay, group, delayInMillis, useRandomPackets));
    }
}
