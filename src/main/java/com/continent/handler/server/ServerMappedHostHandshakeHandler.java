package com.continent.handler.server;

import static io.netty.buffer.Unpooled.directBuffer;
import static io.netty.buffer.Unpooled.unreleasableBuffer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.netty.buffer.ByteBuf;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.util.concurrent.Future;
import io.netty.util.concurrent.FutureListener;

public class ServerMappedHostHandshakeHandler extends ChannelInboundHandlerAdapter {

    public static final ByteBuf FIRST_PACKET = unreleasableBuffer(directBuffer(8)
            .writeLong(0xb7e151628aed2a6bL));
    
    private static final Logger log = LoggerFactory.getLogger(ServerMappedHostHandshakeHandler.class);
    
    private final Future<Channel> future;
    
    public ServerMappedHostHandshakeHandler(Future<Channel> future) {
        super();
        this.future = future;
    }

    @Override
    public void channelRead(final ChannelHandlerContext ctx, Object msg) throws Exception {
        ByteBuf bb = (ByteBuf) msg;
        if (!bb.isReadable(8)) {
            return;
        }
        if (!bb.readSlice(8).equals(FIRST_PACKET)) {
            throw new IllegalStateException();
        }
        bb.release();
        
        ctx.pipeline().remove(this);
        future.addListener(new FutureListener<Channel>() {

            @Override
            public void operationComplete(Future<Channel> future) throws Exception {
                if (!future.isSuccess()) {
                    return;
                }
                
                final Channel channel = future.getNow();
                ctx.channel().writeAndFlush(FIRST_PACKET.duplicate()).addListener(new ChannelFutureListener() {
                    
                    @Override
                    public void operationComplete(ChannelFuture future) throws Exception {
                        if (future.isSuccess()) {
                            channel.read();
                        } else {
                            log.error("Can't write to channel {}", ctx.channel());
                        }
                    }
                });
            }
        });
    }
    
}
