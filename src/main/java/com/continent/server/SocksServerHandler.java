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

import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.codec.socksx.SocksMessage;
import io.netty.handler.codec.socksx.v5.DefaultSocks5InitialResponse;
import io.netty.handler.codec.socksx.v5.DefaultSocks5PasswordAuthResponse;
import io.netty.handler.codec.socksx.v5.Socks5AuthMethod;
import io.netty.handler.codec.socksx.v5.Socks5CommandRequest;
import io.netty.handler.codec.socksx.v5.Socks5CommandRequestDecoder;
import io.netty.handler.codec.socksx.v5.Socks5CommandType;
import io.netty.handler.codec.socksx.v5.Socks5InitialRequest;
import io.netty.handler.codec.socksx.v5.Socks5PasswordAuthRequest;
import io.netty.handler.codec.socksx.v5.Socks5PasswordAuthStatus;

@ChannelHandler.Sharable
public final class SocksServerHandler extends SimpleChannelInboundHandler<SocksMessage> {

    private static final Logger log = LoggerFactory.getLogger(SocksServerHandler.class);

    private final Set<String> whiteListedHosts;
    private final boolean tcpNodelay;
    private final int delayInMillis;
    private final XoShiRo256StarStarRandom splittableRandom;
    private final byte[] randomTimeouts;
    
    public SocksServerHandler(XoShiRo256StarStarRandom splittableRandom, Set<String> whiteListedHosts, boolean tcpNodelay, int delayInMillis, byte[] randomTimeouts) {
        super();
        this.splittableRandom = splittableRandom;
        this.whiteListedHosts = whiteListedHosts;
        this.tcpNodelay = tcpNodelay;
        this.delayInMillis = delayInMillis;
        this.randomTimeouts = randomTimeouts;
    }

    @Override
    public void channelRead0(ChannelHandlerContext ctx, SocksMessage socksRequest) throws Exception {
        if (socksRequest.decoderResult().isFailure()) {
            log.error("Can't decode request: " + socksRequest);
            ctx.close();
            return;
        }
        switch (socksRequest.version()) {
            case SOCKS5:
                if (socksRequest instanceof Socks5InitialRequest) {
                    // auth support example
                    //ctx.pipeline().addFirst(new Socks5PasswordAuthRequestDecoder());
                    //ctx.write(new DefaultSocks5AuthMethodResponse(Socks5AuthMethod.PASSWORD));
                    
                    ctx.pipeline().addAfter("decoder", "Socks5CommandRequestDecoder", new Socks5CommandRequestDecoder());
                    ctx.write(new DefaultSocks5InitialResponse(Socks5AuthMethod.NO_AUTH));
//                    ctx.read();
                } else if (socksRequest instanceof Socks5PasswordAuthRequest) {
                    ctx.pipeline().addAfter("decoder" , null, new Socks5CommandRequestDecoder());
//                    ctx.pipeline().addFirst(new Socks5CommandRequestDecoder());
                    ctx.write(new DefaultSocks5PasswordAuthResponse(Socks5PasswordAuthStatus.SUCCESS));
                } else if (socksRequest instanceof Socks5CommandRequest) {
                    Socks5CommandRequest socks5CmdRequest = (Socks5CommandRequest) socksRequest;
                    if (socks5CmdRequest.type() == Socks5CommandType.CONNECT) {
                        ctx.pipeline().addLast(new SocksServerConnectHandler(splittableRandom, whiteListedHosts, tcpNodelay, delayInMillis, randomTimeouts));
                        ctx.pipeline().remove(this);
                        ctx.fireChannelRead(socksRequest);
                    } else if (socks5CmdRequest.type() == Socks5CommandType.UDP_ASSOCIATE) {
                        log.info("UDP_ASSOCIATE " + socks5CmdRequest);
                    } else {
                        ctx.close();
                    }
                } else {
                    ctx.close();
                }
                break;
            case UNKNOWN:
                ctx.close();
                break;
        }
    }

    @Override
    public void channelReadComplete(ChannelHandlerContext ctx) {
        ctx.flush();
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable throwable) {
        throwable.printStackTrace();
        SocksServerUtils.closeOnFlush(ctx.channel());
    }
}
