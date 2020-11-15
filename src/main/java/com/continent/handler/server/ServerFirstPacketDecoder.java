package com.continent.handler.server;

import com.continent.handler.CipherDecoderHandler;
import com.continent.handler.HandshakePacketSplitter;
import com.continent.handler.client.CipherClientEncoderHandler;
import com.continent.random.RandomDelegator;
import com.continent.random.RandomService;
import com.continent.server.SocksServerHandler;
import com.continent.service.*;
import com.google.common.base.Function;
import com.google.common.util.concurrent.FutureCallback;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.common.util.concurrent.MoreExecutors;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufInputStream;
import io.netty.buffer.ByteBufOutputStream;
import io.netty.buffer.ByteBufUtil;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.ByteToMessageDecoder;
import io.netty.handler.codec.socksx.SocksPortUnificationServerHandler;
import io.netty.util.concurrent.Promise;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Future;

public class ServerFirstPacketDecoder extends ByteToMessageDecoder {

    enum State {DATA, FIRST_STEP, SECOND_STEP}
    
    private static final Logger log = LoggerFactory.getLogger(ServerFirstPacketDecoder.class);
    
    private final RandomService randomService;
    
    private State state = State.DATA;

    private int skipBytes;
    private Future<?> closeChannelFuture;

    private boolean useSSL;
    private int delayInMillis;

    private final HandshakeService handshakeService;
    private Set<String> whiteListedHosts;
    private boolean tcpNodelay;
    private boolean useRandomPackets;
    
    public ServerFirstPacketDecoder(HandshakeService handshakeService,
            RandomService randomService, boolean useSSL, int delayInMillis, Set<String> whiteListedHosts, boolean tcpNodelay, boolean useRandomPackets,
            Future<?> closeChannelFuture) {
        this.useSSL = useSSL;
        this.handshakeService = handshakeService;
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
            if (in.readableBytes() < SessionId.SIZE + Protocol.TUNNEL_TYPE_SIZE + Protocol.DATA_LENGTH_SIZE + Protocol.RANDOM_DATA_LENGTH_SIZE) {
                return;
            }
            in.markReaderIndex();

            closeChannelFuture.cancel(false);

            byte[] sessionId = new byte[SessionId.SIZE];
            in.readBytes(sessionId);

            final SessionData sessionData = handshakeService.getClientSession(sessionId);
            if (sessionData != null) {
                final CryptoService cryptoService = new CryptoService();

                byte[] iv = new byte[CryptoService.MAX_IV_SIZE];
                byte[] newSessionId = new byte[SessionId.SIZE];

                sessionData.getLock().lock();
                sessionData.getServerSessionGenerator().nextBytes(newSessionId);
                sessionData.getServerIVGenerator().nextBytes(iv);
                sessionData.getLock().unlock();

                handshakeService.generateNewClientSessionId(sessionData);

                cryptoService.setEncoderCiphers(sessionData.getServerCiphers(), sessionData.getServerKey(), iv);
                cryptoService.setDecoderCiphers(sessionData.getClientCiphers(), sessionData.getIvData(), sessionData.getClientKey());
                
                ByteBuf tunnel = ctx.alloc().buffer(Protocol.TUNNEL_TYPE_SIZE);
                cryptoService.decrypt(new ByteBufOutputStream(tunnel), new ByteBufInputStream(in), Protocol.TUNNEL_TYPE_SIZE);

                byte tunnelType = tunnel.readByte();
                tunnel.release();

                RandomDelegator randomGenerator = randomService.createRandomDataGenerator();

                if (tunnelType == CipherClientEncoderHandler.SOCKS5_TUNNEL) {
                    
                    ctx.pipeline().remove(HandshakePacketSplitter.class);
                    ctx.pipeline().remove(this);
                    
                    ctx.pipeline().addLast(
                            new SocksPortUnificationServerHandler(),
                            new SocksServerHandler(randomGenerator, whiteListedHosts, tcpNodelay, delayInMillis,
                                    sessionData.getRandomTimeouts())
                            );
                    
                } else if (tunnelType == CipherClientEncoderHandler.PORT_MAPPING_TUNNEL) {
                    
                    ByteBuf addressLen = ctx.alloc().buffer(1);
                    cryptoService.decrypt(new ByteBufOutputStream(addressLen), new ByteBufInputStream(in), 1);
                    byte addressLength = addressLen.readByte();
                    addressLen.release();
                    
                    if (in.readableBytes() < addressLength) {
                        in.resetReaderIndex();
                        return;
                    }
                    
                    ByteBuf address = ctx.alloc().buffer(addressLength);
                    cryptoService.decrypt(new ByteBufOutputStream(address), new ByteBufInputStream(in), addressLength);

                    String addr = address.toString(StandardCharsets.UTF_8);
                    address.release();
                    URI hostAddr = URI.create("//" + addr);
                    
                    ctx.pipeline().remove(HandshakePacketSplitter.class);
                    ctx.pipeline().remove(this);
                    
                    Promise<Channel> connectionPromise = ctx.executor().newPromise();
                    ctx.pipeline().addLast(new ServerMappedHostHandshakeHandler(connectionPromise));
                    ctx.pipeline().addLast(new ServerMappedHostTunnelHandler(hostAddr.getHost(), hostAddr.getPort(), connectionPromise, randomGenerator, delayInMillis, useRandomPackets));
                    
                } else {
                    handshakeService.close(ctx);
                    log.error("Incorrect tunnel type: {}", tunnelType);
                    return;
                }

                if (!handshakeService.checkClientSession(sessionId)) {
                    handshakeService.close(ctx);
                    log.error("Already received message was received again. Someone is probing this server." +
                                    " Channel: {}, Session: {}. Closing this channel!",
                            ctx.channel(), ByteBufUtil.hexDump(sessionId));
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

                CipherServerEncoderHandler encoderHandler = new CipherServerEncoderHandler(randomGenerator, newSessionId, cryptoService);
                CipherDecoderHandler decoderHandler = new CipherDecoderHandler(cryptoService);
                
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
