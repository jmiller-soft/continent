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
package com.continent.handler.server;

import com.continent.handler.BackendHandler;
import com.continent.handler.RandomPacketHandler;
import com.continent.random.XoShiRo256StarStarRandom;
import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.util.concurrent.Promise;

public class ServerMappedHostTunnelHandler extends ChannelInboundHandlerAdapter {

    private final String remoteHost;
    private final int remotePort;
    private final int delayInMillis;

    // As we use inboundChannel.eventLoop() when buildling the Bootstrap this does not need to be volatile as
    // the outboundChannel will use the same EventLoop (and therefore Thread) as the inboundChannel.
    private Channel outboundChannel;    
    private final Promise<Channel> promise;
    private final XoShiRo256StarStarRandom splittableRandom;
    private final boolean useRandomPackets;

    public ServerMappedHostTunnelHandler(String remoteHost, int remotePort, Promise<Channel> promise, XoShiRo256StarStarRandom splittableRandom, int delayInMillis, boolean useRandomPackets) {
        this.remoteHost = remoteHost;
        this.remotePort = remotePort;
        this.promise = promise;
        this.delayInMillis = delayInMillis;
        this.splittableRandom = splittableRandom;
        this.useRandomPackets = useRandomPackets;
    }
    
    @Override
    public void handlerAdded(ChannelHandlerContext ctx) throws Exception {
        final Channel inboundChannel = ctx.channel();

        // Start the connection attempt.
        Bootstrap b = new Bootstrap();
        b.group(inboundChannel.eventLoop())
         .channel(ctx.channel().getClass())
         .handler(new ChannelInitializer<Channel>() {
             @Override
             protected void initChannel(Channel ch) throws Exception {
//                 ch.pipeline().addFirst(new LoggingHandler("uncrypted backend", LogLevel.INFO));
                 
                 if (useRandomPackets) {
                     ch.pipeline().addLast(new RandomPacketHandler(splittableRandom, inboundChannel));
                 }
                 ch.pipeline().addLast(new BackendHandler(splittableRandom, inboundChannel, delayInMillis));
                 ch.pipeline().addLast(new ConnectionHandler(promise));
             }
         })
         .option(ChannelOption.AUTO_READ, false);
//         .option(ChannelOption.SO_KEEPALIVE, true);
        ChannelFuture remoteFuture = b.connect(remoteHost, remotePort);
        outboundChannel = remoteFuture.channel();
        remoteFuture.addListener(new ChannelFutureListener() {
            @Override
            public void operationComplete(ChannelFuture future) {
                if (!future.isSuccess()) {
                    // Close the connection if the connection attempt has failed.
                    inboundChannel.close();
                }
            }
        });
    }
    
    @Override
    public void channelRead(final ChannelHandlerContext ctx, Object msg) {
        if (outboundChannel.isActive()) {
            outboundChannel.writeAndFlush(msg).addListener(new ChannelFutureListener() {
                @Override
                public void operationComplete(ChannelFuture future) {
                    if (future.isSuccess()) {
                        // was able to flush out data, start to read the next chunk
//                        outboundChannel.read();
                        ctx.channel().read();
                    } else {
                        future.channel().close();
                    }
                }
            });
        }
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
        if (outboundChannel != null) {
            closeOnFlush(outboundChannel);
        }
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        cause.printStackTrace();
        closeOnFlush(ctx.channel());
    }

    /**
     * Closes the specified channel after all queued write requests are flushed.
     */
    static void closeOnFlush(Channel ch) {
        if (ch.isActive()) {
            ch.writeAndFlush(Unpooled.EMPTY_BUFFER).addListener(ChannelFutureListener.CLOSE);
        }
    }
}
