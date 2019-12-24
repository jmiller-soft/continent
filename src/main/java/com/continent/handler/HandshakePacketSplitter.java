package com.continent.handler;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Random;
import java.util.concurrent.TimeUnit;

import com.continent.random.RandomService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelOutboundHandlerAdapter;
import io.netty.channel.ChannelPromise;

public class HandshakePacketSplitter extends ChannelOutboundHandlerAdapter {

    private static final Logger log = LoggerFactory.getLogger(HandshakePacketSplitter.class);
    
    private final List<ByteBuf> parts = new ArrayList<>();
    private final RandomService randomService;
    
    public HandshakePacketSplitter(RandomService randomService) {
        super();
        this.randomService = randomService;
    }

    @Override
    public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) throws Exception {
        if (parts.contains(msg)) {
            super.write(ctx, msg, promise);
            return;
        }
        
        // probability to send as single packet is 33%
        if (randomService.getNonceGenerator().nextInt(3) == 0) {
            super.write(ctx, msg, promise);
        } else {
            sendSplitted(ctx, (ByteBuf)msg);
        }
    }
    
    private List<Integer> split(int number) {
        List<Integer> numbers = new ArrayList<>();
        int s = number;
        while (true) {
            int num = randomService.getNonceGenerator().nextInt(number);
            if (s < num) {
                num = s;
            }
            s -= num;
            numbers.add(num);
            if (s == 0) {
                break;
            }
        }
        log.info("packet size {} splitted to {}", number, numbers);
        return numbers;
    }
    
    protected void sendSplitted(ChannelHandlerContext ctx, ByteBuf publicKeyBuf) {
        List<Integer> partsSize = split(publicKeyBuf.readableBytes());
        int s = 0;
        for (Integer partSize : partsSize) {
            ByteBuf part = publicKeyBuf.retainedSlice(s, partSize);
            parts.add(part);
            s += partSize;
        }
        send(ctx, parts.iterator());
        publicKeyBuf.release();
    }

    protected void send(final ChannelHandlerContext ctx, final Iterator<ByteBuf> iterator) {
        if (!iterator.hasNext()) {
            parts.clear();
            return;
        }

        int delay = getRandomNumberInRange(randomService.getNonceGenerator(), 10, 500);
        ctx.executor().schedule(new Runnable() {
            @Override
            public void run() {
                if (!ctx.channel().isActive()) {
                    while (iterator.hasNext()) {
                        iterator.next().release();
                    }
                    return;
                }
                ctx.writeAndFlush(iterator.next()).addListener(new ChannelFutureListener() {
                    @Override
                    public void operationComplete(ChannelFuture future) throws Exception {
                        if (future.isSuccess()) {
                            send(ctx, iterator);
                        } else {
                            log.error("Unable to send packet", future.cause());
                        }
                    }
                });
            }
        }, delay, TimeUnit.MILLISECONDS);
    }

    private static int getRandomNumberInRange(Random r, int min, int max) {
        if (min >= max) {
            throw new IllegalArgumentException("max must be greater than min");
        }

        return r.nextInt((max - min) + 1) + min;
    }

}
