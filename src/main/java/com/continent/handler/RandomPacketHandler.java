package com.continent.handler;

import com.continent.random.RandomDelegator;
import com.continent.random.RandomService;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.TimeUnit;

public class RandomPacketHandler extends ChannelDuplexHandler {

    private static final Logger log = LoggerFactory.getLogger(RandomPacketHandler.class);
    
    private boolean sent;
    private int maxPacketSize;
    private final Channel inboundChannel;
    private final RandomDelegator randomGenerator;
    private final int minTimeout;
    private final int maxTimeout;
    
    private long sentData;
    private long lastSentTime = System.currentTimeMillis();

    public RandomPacketHandler(RandomDelegator randomGenerator, Channel inboundChannel) {
        this(randomGenerator, inboundChannel, 2000, 4000);
    }

    public RandomPacketHandler(RandomDelegator randomGenerator, Channel inboundChannel, int minTimeout, int maxTimeout) {
        super();
        this.inboundChannel = inboundChannel;
        this.randomGenerator = randomGenerator;
        maxPacketSize = randomGenerator.nextInt(5000);
        this.minTimeout = minTimeout;
        this.maxTimeout = maxTimeout;
    }
    
    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        if (msg instanceof ByteBuf) {
            // size of sent data
            int size = ((ByteBuf) msg).readableBytes();
            maxPacketSize = Math.max(maxPacketSize, size);
            
            long currentTime = System.currentTimeMillis();
            if (currentTime - lastSentTime > 1000) {
                sentData = 0;
            }
            lastSentTime = currentTime;
            sentData += size;
        }

        super.channelRead(ctx, msg);

        if (!sent) {
            sent = true;
            schedule(ctx);
        }
    }

    protected void schedule(final ChannelHandlerContext ctx) {
        int maxDelay = minTimeout;
        if (System.currentTimeMillis() - lastSentTime < 1000
                && sentData > 10000) {
            maxDelay = maxTimeout;
        }
        int delay = randomGenerator.nextInt(maxDelay);

        ctx.executor().schedule(new Runnable() {
            @Override
            public void run() {
                if (!inboundChannel.isActive()) {
                    return;
                }
                
                ByteBuf randomDataSize = Unpooled.copyInt(randomGenerator.nextInt(maxPacketSize));
                ByteBuf randomPacket = Unpooled.wrappedBuffer(CipherEncoderHandler.RANDOM_PACKET_HEADER.copy(), randomDataSize);
                
                ChannelFuture f = inboundChannel.writeAndFlush(randomPacket);
                f.addListener(new ChannelFutureListener() {
                    @Override
                    public void operationComplete(ChannelFuture future) throws Exception {
                        if (inboundChannel.isActive()) {
                            schedule(ctx);
                        }
                    }
                });
            }
        }, delay, TimeUnit.MILLISECONDS);
    }

}
