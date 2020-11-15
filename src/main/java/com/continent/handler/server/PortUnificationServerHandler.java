package com.continent.handler.server;

import com.continent.handler.HandshakePacketSplitter;
import com.continent.random.RandomService;
import com.continent.service.CryptoService;
import com.continent.service.HandshakeService;
import com.continent.service.SessionId;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

public class PortUnificationServerHandler extends ByteToMessageDecoder {

    private static final Logger log = LoggerFactory.getLogger(PortUnificationServerHandler.class);
    
    private static final SelfSignedCertificate ssc;

    private Future<?> closeChannelFuture;
    
    private final RandomService randomService;
    
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
    
    public PortUnificationServerHandler(HandshakeService handshakeService, RandomService randomService, int delayInMillis, Set<String> whiteListedHosts, boolean tcpNodelay, boolean useRandomPackets) {
        this.handshakeService = handshakeService;
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
        if (in.readableBytes() < SessionId.SIZE) {
            return;
        }

        in.markReaderIndex();
        byte[] sessionId = new byte[SessionId.SIZE];
        in.readBytes(sessionId);
        in.resetReaderIndex();

        boolean useSsl = false;
        if (handshakeService.getClientSession(sessionId) == null) {
            useSsl = SslHandler.isEncrypted(in);
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
        }

        ctx.pipeline().addLast(new ServerFirstPacketDecoder(handshakeService, randomService, useSsl,
                delayInMillis, whiteListedHosts, tcpNodelay, useRandomPackets, closeChannelFuture));
        ctx.pipeline().addLast(new HandshakePacketSplitter(randomService));
        ctx.pipeline().remove(this);
    }

}
