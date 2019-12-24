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
import java.util.Arrays;
import java.util.List;

import javax.net.ssl.SSLEngine;

import com.continent.handler.BackendHandler;
import com.continent.handler.RandomPacketHandler;
import com.continent.handler.client.CipherClientDecoderHandler;
import com.continent.handler.client.CipherClientEncoderHandler;
import com.continent.handler.client.ClientMappedHostHandshakeHandler;
import com.continent.random.RandomService;
import com.continent.random.XoShiRo256StarStarRandom;
import com.continent.service.CryptoService;
import com.continent.service.HandshakeService;
import com.continent.service.SessionData;
import io.netty.bootstrap.Bootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.group.ChannelGroup;
import io.netty.handler.ssl.ApplicationProtocolConfig;
import io.netty.handler.ssl.ApplicationProtocolConfig.Protocol;
import io.netty.handler.ssl.ApplicationProtocolConfig.SelectedListenerFailureBehavior;
import io.netty.handler.ssl.ApplicationProtocolConfig.SelectorFailureBehavior;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslHandler;
import io.netty.handler.ssl.SslHandshakeCompletionEvent;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;

public class ProxyClientHandler extends ChannelInboundHandlerAdapter {

    private final ChannelGroup group;
    private final HandshakeService handshakeService;
    private final RandomService randomService;
    private final String mappedHost;

    private final boolean tcpNodelay;
    private final List<URI> urls;
    private final Integer delayInMillis;
    private final XoShiRo256StarStarRandom splittableRandom;
    private final boolean useRandomPackets;
    
    public ProxyClientHandler(List<URI> urls, 
            RandomService randomService, HandshakeService handshakeService, String mappedHost, boolean tcpNodelay, ChannelGroup group, Integer delayInMillis, boolean useRandomPackets) {
        this.urls = urls;
        this.randomService = randomService;
        this.mappedHost = mappedHost;
        this.handshakeService = handshakeService;
        this.tcpNodelay = tcpNodelay;
        this.group = group;
        this.delayInMillis = delayInMillis;
        this.splittableRandom = new XoShiRo256StarStarRandom(randomService.getNonceGenerator().nextLong());
        this.useRandomPackets = useRandomPackets;
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) {
        final Channel inboundChannel = ctx.channel();

        int index = randomService.getNonceGenerator().nextInt(urls.size());
        final URI serverUri = urls.get(index);

        // Start the connection attempt.
        Bootstrap b = new Bootstrap();
        b.option(ChannelOption.TCP_NODELAY, tcpNodelay);
        b.group(inboundChannel.eventLoop())
         .channel(ctx.channel().getClass())
         .handler(new ChannelInitializer<Channel>() {
             
             @Override
             protected void initChannel(final Channel serverChannel) throws Exception {
                 SessionData sessionData = handshakeService.getClientSession();
                 
                 CryptoService holder = new CryptoService();
                 holder.setEncoderCiphers(sessionData.getClientCiphers(), randomService, sessionData.getClientKey());
                 
                 group.add(serverChannel);
                 
                 if (serverUri.getScheme().equals("https")) {
                     SslContextBuilder sslContextBuilder = SslContextBuilder.forClient();
                     ApplicationProtocolConfig apn = new ApplicationProtocolConfig(
                             Protocol.ALPN, SelectorFailureBehavior.CHOOSE_MY_LAST_PROTOCOL,
                             SelectedListenerFailureBehavior.ACCEPT, Arrays.asList("h2", "http/1.1"));
                     sslContextBuilder.applicationProtocolConfig(apn);
                     sslContextBuilder.trustManager(InsecureTrustManagerFactory.INSTANCE);
                     
                     SslContext sslContext = sslContextBuilder.build();
                     SSLEngine sslEngine = sslContext.newEngine(serverChannel.alloc(), serverUri.getHost(), serverUri.getPort());
                     SslHandler sslHandler = new SslHandler(sslEngine);
                     serverChannel.pipeline().addLast(sslHandler);
                     serverChannel.pipeline().addLast(new ChannelInboundHandlerAdapter() {
                         
                         volatile boolean sslInitDone;
                         
                         @Override
                         public void channelActive(ChannelHandlerContext ctx) throws Exception {
                             if (sslInitDone) {
                                 super.channelActive(ctx);
                             }
                         }
                         
                         @Override
                         public void userEventTriggered(ChannelHandlerContext ctx, Object evt) throws Exception {
                             if (!sslInitDone && (evt instanceof SslHandshakeCompletionEvent)) {
                                 SslHandshakeCompletionEvent e = (SslHandshakeCompletionEvent) evt;
                                 if (e.isSuccess()) {
                                     sslInitDone = true;
                                     ctx.fireChannelActive();
                                 }
                             }

                             super.userEventTriggered(ctx, evt);
                         }

                     });
                 }
                 
//                     ch.pipeline().addLast(new LoggingHandler("encrypted", LogLevel.INFO));
                 serverChannel.pipeline().addLast(new CipherClientEncoderHandler(splittableRandom, sessionData.getSessionId(), mappedHost, holder));
                 serverChannel.pipeline().addLast(new CipherClientDecoderHandler(handshakeService, holder, 
                         sessionData.getSessionId(), sessionData.getServerCiphers(), sessionData.getServerKey()));
//                     ch.pipeline().addLast(new LoggingHandler("decrypted", LogLevel.INFO));
                 
                 if (mappedHost != null) {
                     serverChannel.pipeline().addLast(new ClientMappedHostHandshakeHandler(inboundChannel));
                 } else {
                     serverChannel.pipeline().addLast(new ChannelInboundHandlerAdapter() {
                         @Override
                        public void channelActive(ChannelHandlerContext ctx) throws Exception {
                             super.channelActive(ctx);
                             
                             // connection completed start to read first data
                             inboundChannel.read();
                             serverChannel.read();
                        }
                     });
                 }
                 
                 serverChannel.pipeline().addLast(new BackendHandler(inboundChannel));
             }
         })
         .option(ChannelOption.AUTO_READ, false)
         .option(ChannelOption.SO_KEEPALIVE, true);

        
        ChannelFuture f = b.connect(serverUri.getHost(), serverUri.getPort());
        Channel serverChannel = f.channel();

        if (useRandomPackets) {
            ctx.pipeline().addLast(new RandomPacketHandler(splittableRandom, serverChannel));
        }
        
        ctx.pipeline().addLast(new BackendHandler(splittableRandom, serverChannel, delayInMillis));
    }

}
