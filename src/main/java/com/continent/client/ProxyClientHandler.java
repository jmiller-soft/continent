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

import com.continent.handler.BackendHandler;
import com.continent.handler.RandomPacketHandler;
import com.continent.handler.client.CipherClientDecoderHandler;
import com.continent.handler.client.CipherClientEncoderHandler;
import com.continent.handler.client.ClientMappedHostHandshakeHandler;
import com.continent.random.RandomDelegator;
import com.continent.random.RandomService;
import com.continent.service.CryptoService;
import com.continent.service.HandshakeService;
import com.continent.service.SessionData;
import com.continent.service.SessionId;
import io.netty.bootstrap.Bootstrap;
import io.netty.channel.*;
import io.netty.channel.group.ChannelGroup;
import io.netty.handler.ssl.*;
import io.netty.handler.ssl.ApplicationProtocolConfig.Protocol;
import io.netty.handler.ssl.ApplicationProtocolConfig.SelectedListenerFailureBehavior;
import io.netty.handler.ssl.ApplicationProtocolConfig.SelectorFailureBehavior;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;

import javax.net.ssl.SSLEngine;
import java.net.URI;
import java.util.Arrays;
import java.util.List;

public class ProxyClientHandler extends ChannelInboundHandlerAdapter {

    private final ChannelGroup group;
    private final HandshakeService handshakeService;
    private final RandomService randomService;
    private final String mappedHost;

    private final boolean tcpNodelay;
    private final List<URI> urls;
    private final Integer delayInMillis;
    private final boolean useRandomPackets;

    private final RandomDelegator randomGenerator;
    
    public ProxyClientHandler(List<URI> urls, 
            RandomService randomService, HandshakeService handshakeService, String mappedHost, boolean tcpNodelay, ChannelGroup group, Integer delayInMillis, boolean useRandomPackets) {
        this.urls = urls;
        this.randomService = randomService;
        this.mappedHost = mappedHost;
        this.handshakeService = handshakeService;
        this.tcpNodelay = tcpNodelay;
        this.group = group;
        this.delayInMillis = delayInMillis;
        this.useRandomPackets = useRandomPackets;
        this.randomGenerator = randomService.createRandomDataGenerator();
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

                 byte[] sessionId = new byte[SessionId.SIZE];
                 byte[] iv = new byte[CryptoService.MAX_IV_SIZE];
                 sessionData.getLock().lock();
                 sessionData.getClientSessionGenerator().nextBytes(sessionId);
                 sessionData.getClientIVGenerator().nextBytes(iv);
                 sessionData.getLock().unlock();

                 handshakeService.generateNewServerSessionId();

                 holder.setEncoderCiphers(sessionData.getClientCiphers(), sessionData.getClientKey(), iv);
                 
//                 group.add(serverChannel);
                 
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
                 serverChannel.pipeline().addLast(new CipherClientEncoderHandler(randomGenerator, sessionId, mappedHost, holder));
                 serverChannel.pipeline().addLast(new CipherClientDecoderHandler(handshakeService, holder, 
                         sessionData.getServerCiphers(), sessionData.getServerKey()));
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
            ctx.pipeline().addLast(new RandomPacketHandler(randomGenerator, serverChannel));
        }
        
        ctx.pipeline().addLast(new BackendHandler(randomGenerator, serverChannel, delayInMillis));
    }

}
