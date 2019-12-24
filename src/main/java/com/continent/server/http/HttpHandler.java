package com.continent.server.http;

import static io.netty.handler.codec.http.HttpResponseStatus.*;
import static io.netty.handler.codec.http.HttpVersion.HTTP_1_1;

import com.continent.server.SocksServerHandler;
import com.continent.handler.server.ServerFirstPacketDecoder;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpUtil;
import io.netty.handler.codec.http.LastHttpContent;
import io.netty.handler.codec.socksx.SocksPortUnificationServerHandler;

public class HttpHandler extends ChannelInboundHandlerAdapter {

    private boolean handlersRemoved = false;

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        if (msg instanceof LastHttpContent) {
            return;
        }
        if (msg instanceof HttpRequest) {
            HttpRequest req = (HttpRequest) msg;
            
            boolean keepAlive = HttpUtil.isKeepAlive(req);
            FullHttpResponse response;
            if (req.uri().equals("/")) {
                ByteBuf content = Unpooled.wrappedBuffer("Open Streams server".getBytes());
                response = new DefaultFullHttpResponse(HTTP_1_1, OK, content);
                response.headers().set(HttpHeaderNames.CONTENT_TYPE, "text/html; charset=utf-8");
                response.headers().setInt(HttpHeaderNames.CONTENT_LENGTH, response.content().readableBytes());
            } else {
                ByteBuf content = Unpooled.wrappedBuffer("404".getBytes());
                response = new DefaultFullHttpResponse(HTTP_1_1, NOT_FOUND, content);
                response.headers().set(HttpHeaderNames.CONTENT_TYPE, "text/html; charset=utf-8");
                response.headers().setInt(HttpHeaderNames.CONTENT_LENGTH, response.content().readableBytes());
            }


            if (!keepAlive) {
                ctx.writeAndFlush(response).addListener(ChannelFutureListener.CLOSE);
                response.headers().set(HttpHeaderNames.CONNECTION, HttpHeaderNames.KEEP_ALIVE);
            } else {
                ctx.writeAndFlush(response);
            }
            
            if (!handlersRemoved) {
                ctx.pipeline().remove(ServerFirstPacketDecoder.class);
                ctx.pipeline().remove(SocksPortUnificationServerHandler.class);
                ctx.pipeline().remove(SocksServerHandler.class);
                handlersRemoved = true;
            }
            return;
        }
        super.channelRead(ctx, msg);
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        cause.printStackTrace();
        ctx.close();
    }
}