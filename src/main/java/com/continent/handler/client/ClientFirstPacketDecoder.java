package com.continent.handler.client;

import java.net.URI;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.google.common.util.concurrent.FutureCallback;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.common.util.concurrent.MoreExecutors;

import com.continent.service.HandshakeService;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.ByteToMessageDecoder;

public class ClientFirstPacketDecoder extends ByteToMessageDecoder {

    private final Logger log = LoggerFactory.getLogger(ClientFirstPacketDecoder.class);

    enum State {FIRST_STEP, SECOND_STEP}
    
    private State state = State.FIRST_STEP;
    
    private final HandshakeService handshakeService;

    private int skipBytes;
    
    public ClientFirstPacketDecoder(HandshakeService handshakeService) {
        super();
        this.handshakeService = handshakeService;
    }
    
    @Override
    public void channelActive(final ChannelHandlerContext ctx) throws Exception {
        ListenableFuture<ByteBuf> future = handshakeService.createClientToServer1stPacket(ctx);
        Futures.addCallback(future, new FutureCallback<ByteBuf>() {
            @Override
            public void onSuccess(ByteBuf publicKeyBuf) {
                ctx.channel().writeAndFlush(publicKeyBuf);
            }
            @Override
            public void onFailure(Throwable t) {
                log.error(t.getMessage(), t);
            }
        }, MoreExecutors.directExecutor());
                
        super.channelActive(ctx);
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
        
        if (state == State.FIRST_STEP) {
            if (in.readableBytes() < HandshakeService.FIRST_SERVER_PACKET_LENGTH) {
                return;
            }
            
            ListenableFuture<ByteBuf> future = handshakeService.createClientToServer2ndPacket(in, ctx, new Function<Integer, Void>() {
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
            if (in.readableBytes() < HandshakeService.ntruEncryptedChunkSize + HandshakeService.tagSize) {
                return;
            }

            skipBytes = handshakeService.handleLastPacket(in, ctx);
        }
    }
    
}
