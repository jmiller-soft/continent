package com.continent.handler.client;

import com.continent.handler.server.ServerMappedHostHandshakeHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.netty.buffer.ByteBuf;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;

public class ClientMappedHostHandshakeHandler extends ChannelInboundHandlerAdapter {

    private static final Logger log = LoggerFactory.getLogger(ClientMappedHostHandshakeHandler.class);
    
    private final Channel inboundChannel;
    
    public ClientMappedHostHandshakeHandler(Channel inboundChannel) {
        super();
        this.inboundChannel = inboundChannel;
    }

    @Override
    public void channelActive(final ChannelHandlerContext ctx) throws Exception {
         super.channelActive(ctx);

         // send FIRST_PACKET to init PORT_MAPPING_TUNNEL connection
         ctx.channel().writeAndFlush(ServerMappedHostHandshakeHandler.FIRST_PACKET.duplicate()).addListener(new ChannelFutureListener() {
             @Override
             public void operationComplete(ChannelFuture future) throws Exception {
                 if (future.isSuccess()) {
                     // waiting for FIRST_PACKET message
                     ctx.channel().read();
                 } else {
                     log.error("Can't connect to {}", ctx.channel().remoteAddress());
                     inboundChannel.close();
                 }
             }
         });
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        ByteBuf bb = (ByteBuf) msg;
        if (!bb.isReadable(8)) {
            return;
        }
        if (!bb.readSlice(8).equals(ServerMappedHostHandshakeHandler.FIRST_PACKET.duplicate())) {
            throw new IllegalStateException();
        }
        ctx.pipeline().remove(this);
        
        if (bb.isReadable()) {
            super.channelRead(ctx, msg);
        } else {
            bb.release();
        }
        
        ctx.channel().read();
        inboundChannel.read();
    }
    
}
