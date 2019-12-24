package com.continent.handler.server;

import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.Future;

import com.continent.handler.CipherDecoderHandler;
import com.continent.handler.HandshakePacketSplitter;
import com.continent.handler.client.CipherClientEncoderHandler;
import com.continent.random.RandomService;
import com.continent.random.XoShiRo256StarStarRandom;
import com.continent.server.SocksServerHandler;
import io.netty.buffer.ByteBufUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.google.common.util.concurrent.FutureCallback;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.common.util.concurrent.MoreExecutors;

import com.continent.service.CryptoService;
import com.continent.service.HandshakeService;
import com.continent.service.SessionData;
import io.netty.buffer.ByteBuf;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.ByteToMessageDecoder;
import io.netty.handler.codec.socksx.SocksPortUnificationServerHandler;
import io.netty.util.concurrent.Promise;

public class ServerFirstPacketDecoder extends ByteToMessageDecoder {

    enum State {DATA, FIRST_STEP, SECOND_STEP}
    
    private static final Logger log = LoggerFactory.getLogger(ServerFirstPacketDecoder.class);
    
    private final RandomService randomService;
    
    private State state = State.DATA;
    private final Collection<SessionData> sessions;
    
    private int skipBytes;
    private Future<?> closeChannelFuture;
    private SessionData currentSessionData;

    private boolean useSSL;
    private int delayInMillis;

    private final HandshakeService handshakeService;
    private Set<String> whiteListedHosts;
    private boolean tcpNodelay;
    private boolean useRandomPackets;
    
    public ServerFirstPacketDecoder(HandshakeService handshakeService, Queue<SessionData> sessions, 
            RandomService randomService, boolean useSSL, int delayInMillis, Set<String> whiteListedHosts, boolean tcpNodelay, boolean useRandomPackets,
            Future<?> closeChannelFuture) {
        this.useSSL = useSSL;
        this.handshakeService = handshakeService;
        this.sessions = sessions;
        this.randomService = randomService;
        this.delayInMillis = delayInMillis;
        this.whiteListedHosts = whiteListedHosts;
        this.tcpNodelay = tcpNodelay;
        this.useRandomPackets = useRandomPackets;
        this.closeChannelFuture = closeChannelFuture;
    }
    
    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        try {
            super.channelRead(ctx, msg);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    @Override
    protected void decode(final ChannelHandlerContext ctx, ByteBuf in, List<Object> out) throws Exception {
        if (skipBytes > 0) {
            int skippedBytes = Math.min(skipBytes, in.readableBytes());
            in.skipBytes(skippedBytes);
            skipBytes -= skippedBytes;

            if (skipBytes > 0) {
                return;
            }
        }
        
        if (state == State.DATA) {
            if (in.readableBytes() < CryptoService.MAX_IV_SIZE + CryptoService.MAC_ID_SIZE + CryptoService.TUNNEL_TYPE_SIZE + CryptoService.DATA_LENGTH_SIZE + CryptoService.RANDOM_DATA_LENGTH_SIZE) {
                return;
            }
            in.markReaderIndex();
            
            closeChannelFuture.cancel(false);
            
            Collection<SessionData> userSessions = sessions;
            if (currentSessionData != null) {
                userSessions = Collections.singleton(currentSessionData);
            }
            
            for (final SessionData sessionData : userSessions) {
                in.resetReaderIndex();
                
                CryptoService holder = new CryptoService();
                byte[] sessionMac = holder.checkSessionMac(in, sessionData.getSessionId());
                if (sessionMac == null) {
                    continue;
                }
                
                in.resetReaderIndex();
                
                currentSessionData = sessionData;
                
                byte[] ivData = new byte[CryptoService.MAX_IV_SIZE];
                in.readBytes(ivData);
                in.skipBytes(CryptoService.MAC_ID_SIZE);
                
                holder.setEncoderCiphers(sessionData.getServerCiphers(), randomService, sessionData.getServerKey());
                holder.setDecoderCiphers(sessionData.getClientCiphers(), ivData, sessionData.getClientKey());
                
                ByteBuf tunnel = ctx.alloc().buffer(1);
                holder.decrypt(tunnel, in, 1);

                byte tunnelType = tunnel.readByte();
                tunnel.release();

                XoShiRo256StarStarRandom splittableRandom = new XoShiRo256StarStarRandom(randomService.getNonceGenerator().nextLong());
                
                if (tunnelType == CipherClientEncoderHandler.SOCKS5_TUNNEL) {
                    
                    ctx.pipeline().remove(HandshakePacketSplitter.class);
                    ctx.pipeline().remove(this);
                    
                    ctx.pipeline().addLast(
                            new SocksPortUnificationServerHandler(),
                            new SocksServerHandler(splittableRandom, whiteListedHosts, tcpNodelay, delayInMillis,
                                    sessionData.getRandomTimeouts())
                            );
                    
                } else if (tunnelType == CipherClientEncoderHandler.PORT_MAPPING_TUNNEL) {
                    
                    ByteBuf addressLen = ctx.alloc().buffer(1);
                    holder.decrypt(addressLen, in, 1);
                    byte addressLength = addressLen.readByte();
                    addressLen.release();
                    
                    if (in.readableBytes() < addressLength) {
                        in.resetReaderIndex();
                        return;
                    }
                    
                    ByteBuf address = ctx.alloc().buffer(addressLength);
                    holder.decrypt(address, in, addressLength);

                    String addr = address.toString(StandardCharsets.UTF_8);
                    address.release();
                    URI hostAddr = URI.create("//" + addr);
                    
                    ctx.pipeline().remove(HandshakePacketSplitter.class);
                    ctx.pipeline().remove(this);
                    
                    Promise<Channel> connectionPromise = ctx.executor().newPromise();
                    ctx.pipeline().addLast(new ServerMappedHostHandshakeHandler(connectionPromise));
                    ctx.pipeline().addLast(new ServerMappedHostTunnelHandler(hostAddr.getHost(), hostAddr.getPort(), connectionPromise, splittableRandom, delayInMillis, useRandomPackets));
                    
                } else {
                    handshakeService.close(ctx);
                    log.error("Incorrect tunnel type: {}", tunnelType);
                    return;
                }

                long tagId = ByteBuffer.wrap(sessionMac).getLong();
                if (!sessionData.addSessionMac(tagId)) {
                    handshakeService.close(ctx);
                    log.error("Already received message was received again. Someone is probing this server." +
                                    " Session Mac: {}, Channel: {}, Authenticated macs: {}, Session: {}. Closing this channel!",
                            ByteBufUtil.hexDump(sessionMac), ctx.channel(), sessionData.countSessionsMacs(),
                            ByteBufUtil.hexDump(sessionData.getSessionId()));
                    return;
                }

                sessionData.updateLastAccessTime();
                sessionData.incUsage();

                ctx.channel().closeFuture().addListener(new ChannelFutureListener() {
                    @Override
                    public void operationComplete(ChannelFuture future) throws Exception {
                        sessionData.updateLastAccessTime();
                        sessionData.decUsage();
                    }
                });

                CipherServerEncoderHandler encoderHandler = new CipherServerEncoderHandler(splittableRandom, sessionData.getSessionId(), holder);
                CipherDecoderHandler decoderHandler = new CipherDecoderHandler(holder);
                
                if (useSSL) {
                    ctx.pipeline().addAfter("sslHandler", "encoder", encoderHandler);
                    ctx.pipeline().addAfter("sslHandler", "decoder", decoderHandler);
                } else {
                    ctx.pipeline().addFirst("encoder", encoderHandler);
                    ctx.pipeline().addFirst("decoder", decoderHandler);
                }
                
                in.retain();
                
                if (useSSL) {
                    ctx.pipeline().firstContext().fireChannelRead(in);
                } else {
                    ctx.pipeline().fireChannelRead(in);
                }
                return;
            }
            
            in.resetReaderIndex();
            state = State.FIRST_STEP;
        }
        
        if (state == State.FIRST_STEP) {
            if (in.readableBytes() < HandshakeService.publicKeyIVSize + HandshakeService.ntruPublicKeySize + HandshakeService.tagSize) {
                return;
            }
            
            ListenableFuture<ByteBuf> future = handshakeService.createServerToClient1stPacket(in, ctx, new Function<Integer, Void>() {
                @Override
                public Void apply(Integer r) {
                    skipBytes = r;
                    return null;
                }
            });
            Futures.addCallback(future, new FutureCallback<ByteBuf>() {
                @Override
                public void onSuccess(ByteBuf packet) {
                    ctx.channel().writeAndFlush(packet);
                    state = State.SECOND_STEP;
                }
                @Override
                public void onFailure(Throwable t) {
                }
            }, MoreExecutors.directExecutor());
        } else if (state == State.SECOND_STEP) {
            if (in.readableBytes() < HandshakeService.ntruEncryptedChunkSize*HandshakeService.ntruClientChunks + HandshakeService.tagSize) {
                return;
            }
            
            ListenableFuture<ByteBuf> future = handshakeService.createServerToClient2ndPacket(in, ctx, new Function<Integer, Void>() {
                @Override
                public Void apply(Integer r) {
                    skipBytes = r;
                    return null;
                }
            });
            Futures.addCallback(future, new FutureCallback<ByteBuf>() {
                @Override
                public void onSuccess(ByteBuf packet) {
                    ctx.channel().writeAndFlush(packet);
                }
                @Override
                public void onFailure(Throwable t) {
                }
            }, MoreExecutors.directExecutor());
        }
    }

}
