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

import com.continent.random.RandomService;
import com.continent.random.entropy.EntropySource;
import com.continent.random.entropy.NativeJitterEntropy;
import com.continent.service.HandshakeService;
import com.google.common.util.concurrent.*;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.group.ChannelGroup;
import io.netty.channel.group.DefaultChannelGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;

import java.io.*;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map.Entry;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

public final class ProxyClient {

    private static final Logger log = LoggerFactory.getLogger(ProxyClient.class);

    private EventLoopGroup bossGroup;
    private EventLoopGroup workerGroup;

    private volatile RandomService randomService;
    private volatile HandshakeService handshakeService;
    
    public ProxyClient() {
    }
    
    public void init(File file) throws FileNotFoundException, InterruptedException, ExecutionException {
        ListenableFuture<Void> future = init(new FileInputStream(file));
        future.get();
        
        Thread.sleep(Long.MAX_VALUE);
    }
    
    public void shutdown() {
        if (handshakeService != null
                && handshakeService.getClientSession() != null) {
            handshakeService.getClientSession().clear();
        }
        if (randomService != null) {
            randomService.shutdown();
        }

        bossGroup.shutdownGracefully();
        workerGroup.shutdownGracefully();
    }

    public ListenableFuture<Void> init(InputStream settingStream) {
        Yaml yaml = new Yaml(new Constructor(ClientConfig.class));
        final ClientConfig config;
        
        try {
            config = yaml.load(settingStream);
        } finally {
            try {
                settingStream.close();
            } catch (IOException e) {
                // empty
            }
        }

        return init(config);
    }

    public ListenableFuture<Void> init(final ClientConfig config) {
        if (config.getKey() == null) {
            throw new IllegalStateException("Client key is not defined!");
        }
        if (config.getServers() == null) {
            throw new IllegalStateException("Servers are not defined!");
        }

        final List<URI> urls = new ArrayList<>();
        for (String server : config.getServers()) {
            urls.add(URI.create(server));
        }
        // Configure the bootstrap.
        bossGroup = new NioEventLoopGroup(1);
        workerGroup = new NioEventLoopGroup();
        final ChannelGroup group = new DefaultChannelGroup(workerGroup.next());

        Runtime.getRuntime().addShutdownHook(new Thread() {
            @Override
            public void run() {
                shutdown();
            }
        });

        final SettableFuture<Void> result = SettableFuture.create();
        final ExecutorService executor = Executors.newFixedThreadPool(1);
        executor.execute(new Runnable() {
            @Override
            public void run() {
                randomService = new RandomService(config.getNonceSeedInterval(), config.getKeySeedInterval());
                handshakeService = new HandshakeService(executor, randomService, workerGroup, config.getKey(), urls, group);

                ListenableFuture<Void> future = handshakeService.connect();
                Futures.addCallback(future, new FutureCallback<Void>() {
                    @Override
                    public void onSuccess(Void res) {
                        if (config.getKeyRotationInterval() != null) {
                            scheduleReHandshake(config);
                        }

                        final AtomicInteger counter = new AtomicInteger(1);

                        ChannelFutureListener listener = new ChannelFutureListener() {
                            @Override
                            public void operationComplete(ChannelFuture future) throws Exception {
                                if (!future.isSuccess()) {
                                    result.setException(future.cause());
                                    return;
                                }

                                if (counter.decrementAndGet() == 0) {
                                    result.set(null);
                                }
                            }
                        };

                        try {
                            if (config.getPortMapping() != null) {
                                counter.addAndGet(config.getPortMapping().size());
                                for (Entry<Integer, String> entry : config.getPortMapping().entrySet()) {
                                    int port = entry.getKey();
                                    String mappedHost = entry.getValue();

                                    ServerBootstrap portMappingServer = new ServerBootstrap();
                                    portMappingServer.group(bossGroup, workerGroup)
                                    .channel(NioServerSocketChannel.class)
                                    .childHandler(new ProxyClientInitializer(urls,
                                            randomService, handshakeService, mappedHost, config.isTcpNoDelay(), group, config.getMaxWriteDelayMs(), config.isUseRandomPackets()))
                                    .childOption(ChannelOption.AUTO_READ, false)
                                    .childOption(ChannelOption.TCP_NODELAY, config.isTcpNoDelay())
                                    .bind(port).addListener(listener);

                                    log.info("port {} mapped to {}", port, mappedHost);
                                }
                            }

                            ServerBootstrap b = new ServerBootstrap();
                            b.group(bossGroup, workerGroup)
                            .channel(NioServerSocketChannel.class)
                            .childHandler(new ProxyClientInitializer(urls,
                                    randomService, handshakeService, null, config.isTcpNoDelay(), group, config.getMaxWriteDelayMs(), config.isUseRandomPackets()))
                            .childOption(ChannelOption.AUTO_READ, false)
                            .childOption(ChannelOption.TCP_NODELAY, config.isTcpNoDelay());
                            b.bind(config.getPort()).addListener(listener);

                            log.info("Proxying *:{} to {}", config.getPort(), urls);
                        } catch (Exception e) {
                            e.printStackTrace();
                        } finally {
//                            executor.shutdown();
//                            bossGroup.shutdownGracefully();
//                            workerGroup.shutdownGracefully();
                        }
                    }

                    @Override
                    public void onFailure(Throwable t) {
                        result.setException(t);
                    }
                }, MoreExecutors.directExecutor());
            }
        });


        return result;
    }

    private void scheduleReHandshake(final ClientConfig config) {
        String[] parts = config.getKeyRotationInterval().split(":");
        int interval = Integer.valueOf(parts[0]);
        if (parts.length > 1) {
            int diff = Integer.valueOf(parts[1]) - Integer.valueOf(parts[0]);
            interval = Integer.valueOf(parts[0]) + randomService.getNonceGenerator().nextInt(diff);
        }

        workerGroup.schedule(new Runnable() {
            @Override
            public void run() {
                handshakeService.connect();
                scheduleReHandshake(config);
            }
        }, interval, TimeUnit.SECONDS);
    }

    public static void main(String[] args) throws Exception {
        ProxyClient client = new ProxyClient();
        client.init(new File(args[0]));
    }

}
