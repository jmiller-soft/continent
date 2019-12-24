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

import java.util.Set;

import com.continent.random.XoShiRo256StarStarRandom;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.continent.handler.BackendHandler;
import com.continent.handler.RandomPacketHandler;
import com.continent.handler.server.ConnectionHandler;
import io.netty.bootstrap.Bootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelOption;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.socksx.SocksMessage;
import io.netty.handler.codec.socksx.v5.DefaultSocks5CommandResponse;
import io.netty.handler.codec.socksx.v5.Socks5CommandRequest;
import io.netty.handler.codec.socksx.v5.Socks5CommandStatus;
import io.netty.util.concurrent.Future;
import io.netty.util.concurrent.FutureListener;
import io.netty.util.concurrent.Promise;

@ChannelHandler.Sharable
public final class SocksServerConnectHandler extends SimpleChannelInboundHandler<SocksMessage> {

    private static final Logger log = LoggerFactory.getLogger(SocksServerConnectHandler.class);
    private final Logger serverHostsLog = LoggerFactory.getLogger("server-hosts-log");
    
    private final Bootstrap b = new Bootstrap();

    private final Set<String> whiteListedHosts;
    private final boolean tcpNodelay;
    private final int delayInMillis;
    private final XoShiRo256StarStarRandom splittableRandom;
    private final byte[] randomTimeouts;
    
    public SocksServerConnectHandler(XoShiRo256StarStarRandom splittableRandom, Set<String> whiteListedHosts, boolean tcpNodelay, int delayInMillis, byte[] randomTimeouts) {
        this.splittableRandom = splittableRandom;
        this.whiteListedHosts = whiteListedHosts;
        this.tcpNodelay = tcpNodelay;
        this.delayInMillis = delayInMillis;
        this.randomTimeouts = randomTimeouts;
    }

    @Override
    public void channelRead0(final ChannelHandlerContext ctx, final SocksMessage message) throws Exception {
        if (message instanceof Socks5CommandRequest) {
            final Socks5CommandRequest request = (Socks5CommandRequest) message;
            Promise<Channel> promise = ctx.executor().newPromise();
            promise.addListener(
                    new FutureListener<Channel>() {
                        @Override
                        public void operationComplete(final Future<Channel> future) throws Exception {
                            final Channel outboundChannel = future.getNow();
                            if (future.isSuccess()) {
                                ChannelFuture responseFuture =
                                        ctx.channel().writeAndFlush(new DefaultSocks5CommandResponse(
                                                Socks5CommandStatus.SUCCESS,
                                                request.dstAddrType(),
                                                request.dstAddr(),
                                                request.dstPort()));

                                responseFuture.addListener(new ChannelFutureListener() {
                                    @Override
                                    public void operationComplete(ChannelFuture channelFuture) {
                                        if (ctx.pipeline().get(SocksServerConnectHandler.class) != null) {
                                            ctx.pipeline().remove(SocksServerConnectHandler.this);
                                        } else {
                                            log.warn("Can't find SocksServerConnectHandler for {}", ctx.pipeline().channel());
                                            channelFuture.channel().close();
                                        }
                                        
                                        if (randomTimeouts[0] > 0) {
                                            outboundChannel.pipeline().addLast(new RandomPacketHandler(splittableRandom, ctx.channel(), randomTimeouts[0]*100, randomTimeouts[1]*100));
                                        }
                                        outboundChannel.pipeline().addLast(new BackendHandler(splittableRandom, ctx.channel(), delayInMillis));
                                        ctx.pipeline().addLast(new BackendHandler(outboundChannel));
//                                        outboundChannel.pipeline().addLast(new SocksRelayHandler(ctx.channel(), true));
//                                        ctx.pipeline().addLast(new SocksRelayHandler(outboundChannel, false));
                                    }
                                });
                            } else {
                                ctx.channel().writeAndFlush(new DefaultSocks5CommandResponse(
                                        Socks5CommandStatus.FAILURE, request.dstAddrType()));
                                SocksServerUtils.closeOnFlush(ctx.channel());
                            }
                        }
                    });

            final Channel inboundChannel = ctx.channel();
            b.group(inboundChannel.eventLoop())
                    .channel(NioSocketChannel.class)
                    .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 10000)
                    .option(ChannelOption.AUTO_READ, false)
                    .option(ChannelOption.TCP_NODELAY, tcpNodelay)
//                    .option(ChannelOption.SO_KEEPALIVE, true)
                    .handler(new ConnectionHandler(promise));

            if (!whiteListedHosts.isEmpty()) {
                serverHostsLog.debug("connection: {} host: {}:", inboundChannel.remoteAddress(), request.dstAddr(), request.dstPort());
                boolean whiteListed = false;
                for (String whiteListedHost : whiteListedHosts) {
                    if (request.dstAddr().endsWith(whiteListedHost)) {
                        whiteListed = true;
                    }
                }
                
                if (!whiteListed) {
                    serverHostsLog.debug("host: {}:{} not whitelisted, connection: {}", request.dstAddr(), request.dstPort(), inboundChannel.remoteAddress());
                    ctx.channel().writeAndFlush(
                            new DefaultSocks5CommandResponse(Socks5CommandStatus.FAILURE, request.dstAddrType()));
                    SocksServerUtils.closeOnFlush(ctx.channel());
                    return;
                }
            }
            
            b.connect(request.dstAddr(), request.dstPort()).addListener(new ChannelFutureListener() {
                @Override
                public void operationComplete(ChannelFuture future) throws Exception {
                    if (future.isSuccess()) {
                        future.channel().read();
                        // Connection established use handler provided results
                    } else {
                        // Close the connection if the connection attempt has failed.
                        ctx.channel().writeAndFlush(
                                new DefaultSocks5CommandResponse(Socks5CommandStatus.FAILURE, request.dstAddrType()));
                        SocksServerUtils.closeOnFlush(ctx.channel());
                    }
                }
            });
        } else {
            ctx.close();
        }
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        SocksServerUtils.closeOnFlush(ctx.channel());
    }
}
