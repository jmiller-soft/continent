package com.continent.handler.server;

import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.List;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import com.continent.handler.HandshakePacketSplitter;
import com.continent.random.RandomService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.continent.service.HandshakeService;
import com.continent.service.SessionData;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.ByteToMessageDecoder;
import io.netty.handler.ssl.ApplicationProtocolConfig;
import io.netty.handler.ssl.ApplicationProtocolConfig.Protocol;
import io.netty.handler.ssl.ApplicationProtocolConfig.SelectedListenerFailureBehavior;
import io.netty.handler.ssl.ApplicationProtocolConfig.SelectorFailureBehavior;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslHandler;
import io.netty.handler.ssl.util.SelfSignedCertificate;

public class PortUnificationServerHandler extends ByteToMessageDecoder {

    private static final Logger log = LoggerFactory.getLogger(PortUnificationServerHandler.class);
    
    private static final SelfSignedCertificate ssc;

    private Future<?> closeChannelFuture;
    
    private final RandomService randomService;
    
    private final Queue<SessionData> sessions;
    
    private int delayInMillis;

    private final HandshakeService handshakeService;
    private Set<String> whiteListedHosts;
    private boolean tcpNodelay;
    private boolean useRandomPackets;
    
    static {
        try {
            ssc = new SelfSignedCertificate("localhost");
        } catch (CertificateException e) {
            throw new IllegalStateException(e);
        }
    }
    
    public PortUnificationServerHandler(HandshakeService handshakeService, Queue<SessionData> sessions, 
            RandomService randomService, int delayInMillis, Set<String> whiteListedHosts, boolean tcpNodelay, boolean useRandomPackets) {
        this.handshakeService = handshakeService;
        this.sessions = sessions;
        this.randomService = randomService;
        this.delayInMillis = delayInMillis;
        this.whiteListedHosts = whiteListedHosts;
        this.tcpNodelay = tcpNodelay;
        this.useRandomPackets = useRandomPackets;
    }

    @Override
    public void channelActive(final ChannelHandlerContext ctx) throws Exception {
        closeChannelFuture = ctx.executor().schedule(new Runnable() {
            @Override
            public void run() {
                ctx.channel().close();
                log.info("Client with ip {} opened channel but didn't send any data! Channel closed!",
                        ctx.channel().remoteAddress());
            }
        }, 1, TimeUnit.MINUTES);
        super.channelActive(ctx);
    }
    
    @Override
    protected void decode(ChannelHandlerContext ctx, ByteBuf in, List<Object> out) throws Exception {
        if (in.readableBytes() < 5) {
            return;
        }
        
        boolean useSsl = SslHandler.isEncrypted(in);
        if (useSsl) {
            ApplicationProtocolConfig apn = new ApplicationProtocolConfig(
                    Protocol.ALPN, SelectorFailureBehavior.CHOOSE_MY_LAST_PROTOCOL,
                    SelectedListenerFailureBehavior.ACCEPT, Arrays.asList("http/1.1"));
            SslContext sslCtx = SslContextBuilder
                                    .forServer(ssc.certificate(), ssc.privateKey())
                                    .applicationProtocolConfig(apn)
                                    .build();
            ctx.pipeline().addLast("sslHandler", sslCtx.newHandler(ctx.alloc()));
        }
        
        ctx.pipeline().addLast(new ServerFirstPacketDecoder(handshakeService, sessions, randomService, useSsl, 
                delayInMillis, whiteListedHosts, tcpNodelay, useRandomPackets, closeChannelFuture));
        ctx.pipeline().addLast(new HandshakePacketSplitter(randomService));
        ctx.pipeline().remove(this);
    }

}
