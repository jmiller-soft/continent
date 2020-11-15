package com.continent.handler;

import java.io.IOException;
import java.util.List;

import com.continent.service.Protocol;
import io.netty.buffer.ByteBufInputStream;
import io.netty.buffer.ByteBufOutputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.continent.service.CryptoService;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.ByteToMessageDecoder;

public class CipherDecoderHandler extends ByteToMessageDecoder {

    private static final Logger log = LoggerFactory.getLogger(CipherDecoderHandler.class);
    
    protected final CryptoService holder;

    private int skipBytes;
    private int readNextBytes;
    
    public CipherDecoderHandler(CryptoService cryptoService) {
        this.holder = cryptoService;
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
    protected void decode(ChannelHandlerContext ctx, ByteBuf input, List<Object> out) throws Exception {
        if (readNextBytes == 0 && skipBytes > 0) {
            int skippedBytes = Math.min(skipBytes, input.readableBytes());
            input.skipBytes(skippedBytes);
            skipBytes -= skippedBytes;
        }
        
        decrypt(ctx, input, out);
    }

    protected void decrypt(ChannelHandlerContext ctx, ByteBuf input, List<Object> out) throws IOException {
        ByteBuf output = null;
        
        if (readNextBytes > 0) {
            int readBytes = Math.min(readNextBytes, input.readableBytes());
            readNextBytes = readNextBytes - readBytes;
            
            output = ctx.alloc().buffer(readBytes);
            holder.decrypt(new ByteBufOutputStream(output), new ByteBufInputStream(input), readBytes);
        } else {
            input.markReaderIndex();
            if (input.readableBytes() < Protocol.DATA_LENGTH_SIZE + Protocol.RANDOM_DATA_LENGTH_SIZE) {
                return;
            }
            output = ctx.alloc().buffer(input.readableBytes());
            
            holder.decrypt(new ByteBufOutputStream(output), new ByteBufInputStream(input), Protocol.DATA_LENGTH_SIZE + Protocol.RANDOM_DATA_LENGTH_SIZE);
            
            if (!decrypt(ctx, input, output)) {
                return;
            }
        }
        out.add(output);
    }

    protected boolean decrypt(ChannelHandlerContext ctx, ByteBuf input, ByteBuf output) throws IOException {
        int packetLength = output.readInt();
        if (packetLength < 0 || packetLength > 66000) {
            log.error("packetLength has wrong value: {}, channel: {}", packetLength, ctx.channel());
            output.release();
            return false;
        }
        int randomLength = output.readInt();
        if (randomLength < 0 || randomLength > 66000) {
            log.error("randomLength has wrong value: {}, channel: {}", randomLength, ctx.channel());
            output.release();
            return false;
        }
        
        
        if (input.readableBytes() < packetLength) {
            readNextBytes = packetLength - input.readableBytes();
            packetLength = input.readableBytes();
        }

        holder.decrypt(new ByteBufOutputStream(output), new ByteBufInputStream(input), packetLength);

        int skippedBytes = Math.min(randomLength, input.readableBytes());
        input.skipBytes(skippedBytes);
        skipBytes = randomLength - skippedBytes;

        return true;
    }

}
