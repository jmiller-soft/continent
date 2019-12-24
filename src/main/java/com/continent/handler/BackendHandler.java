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
package com.continent.handler;

import java.util.concurrent.TimeUnit;

import com.continent.random.XoShiRo256StarStarRandom;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;

public class BackendHandler extends ChannelInboundHandlerAdapter {

    private final Channel inboundChannel;
    private final Integer delayInMillis;
    private final XoShiRo256StarStarRandom splittableRandom;

    public BackendHandler(Channel inboundChannel) {
        this(null, inboundChannel, 0);
    }
    
    public BackendHandler(XoShiRo256StarStarRandom splittableRandom, Channel inboundChannel, Integer delayInMillis) {
        this.inboundChannel = inboundChannel;
        this.delayInMillis = delayInMillis;
        this.splittableRandom = splittableRandom;
    }


    @Override
    public void channelRead(final ChannelHandlerContext ctx, final Object msg) {
//        if (((ByteBuf) msg).readableBytes() > 5) {
//            ByteBuf in = ((ByteBuf) msg).copy();
//            System.out.println("out ch " + ctx.channel() +  " msg " + in.toString(StandardCharsets.UTF_8));
//            in.release();
//        }
        
        if (delayInMillis != null && delayInMillis > 0) {
            ctx.executor().schedule(new Runnable() {
                @Override
                public void run() {
                    send(ctx, msg);
                }
            }, splittableRandom.nextInt(delayInMillis), TimeUnit.MILLISECONDS);
        } else {
            send(ctx, msg);
        }
    }

    protected void send(final ChannelHandlerContext ctx, Object msg) {
        inboundChannel.writeAndFlush(msg).addListener(new ChannelFutureListener() {
            @Override
            public void operationComplete(ChannelFuture future) {
                if (future.isSuccess()) {
                    ctx.channel().read();
                } else {
                    future.channel().close();
                }
            }
        });
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
        closeOnFlush(inboundChannel);
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        cause.printStackTrace();
        closeOnFlush(ctx.channel());
    }
    
    static void closeOnFlush(Channel ch) {
        if (ch.isActive()) {
            ch.writeAndFlush(Unpooled.EMPTY_BUFFER).addListener(ChannelFutureListener.CLOSE);
        }
    }

}
