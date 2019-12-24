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

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import com.continent.random.RandomService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;

import com.google.common.io.BaseEncoding;

import com.continent.service.SessionData;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioServerSocketChannel;

public final class ProxyServer {

    static final Logger log = LoggerFactory.getLogger(ProxyServer.class);

    
    public void init(String configFile) throws IOException, InterruptedException {
        Path settingsPath = Paths.get("").toAbsolutePath().resolve(configFile);

        Yaml yaml = new Yaml(new Constructor(ServerConfig.class));
        ServerConfig config;
        try (InputStream is = Files.newInputStream(settingsPath)) {
            config = yaml.load(is);
        }

        Map<byte[], byte[]> id2PubKey = new HashMap<>();
        for (String entry : config.getKeys()) {
            String[] parts = entry.split(":");
            byte[] id = BaseEncoding.base64().decode(parts[0]);
            byte[] pubKey = BaseEncoding.base64().decode(parts[1]);
            id2PubKey.put(id, pubKey);
        }
        
        if (id2PubKey.isEmpty()) {
            throw new IllegalStateException("Client keys are not defined!");
        }
        
        RandomService randomService = new RandomService();

        ExecutorService executor = Executors.newFixedThreadPool(1);
        EventLoopGroup bossGroup = new NioEventLoopGroup(1);
        EventLoopGroup workerGroup = new NioEventLoopGroup();
        
        final Queue<SessionData> sessions = new ConcurrentLinkedQueue<>();
        workerGroup.scheduleWithFixedDelay(new Runnable() {
            @Override
            public void run() {
                for (Iterator<SessionData> iterator = sessions.iterator(); iterator.hasNext();) {
                    SessionData sessionData = iterator.next();
                    if (System.currentTimeMillis() - sessionData.getLastAccessTime() > TimeUnit.HOURS.toMillis(1)
                            && sessionData.getUsage() == 0) {
                        iterator.remove();
                        log.info("Session removed {}. Sessions remain: {}", sessionData.countSessionsMacs(), sessions.size());
                        sessionData.clear();
                    }
                }
            }
        }, 1, 1, TimeUnit.MINUTES);
        
        try {
            ServerBootstrap b = new ServerBootstrap();
            b.group(bossGroup, workerGroup)
             .childOption(ChannelOption.TCP_NODELAY, config.isTcpNoDelay())
             .childOption(ChannelOption.SO_KEEPALIVE, true)
             .channel(NioServerSocketChannel.class)
//             .handler(new LoggingHandler(LogLevel.TRACE))
             .childHandler(new ProxyServerInitializer(randomService, sessions, config.getWhiteListedHosts(), executor, id2PubKey, 
                                 config.isTcpNoDelay(), config.getMaxWriteDelayMs(), config.isUseRandomPackets()));
            b.bind(config.getPort()).sync().channel().closeFuture().sync();
        } finally {
            executor.shutdown();
            bossGroup.shutdownGracefully();
            workerGroup.shutdownGracefully();
        }
    }
}
