package com.continent.handler.client;

import com.continent.handler.CipherDecoderHandler;
import com.continent.service.*;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufInputStream;
import io.netty.buffer.ByteBufOutputStream;
import io.netty.buffer.ByteBufUtil;
import io.netty.channel.ChannelHandlerContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.List;

public class CipherClientDecoderHandler extends CipherDecoderHandler {

    private static final Logger log = LoggerFactory.getLogger(CipherClientDecoderHandler.class);
    
    private final HandshakeService handshakeService;
    private final List<Object> serverCiphers;
    private final byte[] serverKeys;

    private boolean firstPacket = true;
    
    public CipherClientDecoderHandler(HandshakeService handshakeService, CryptoService holder, List<Object> serverCiphers, byte[] serverKeys) {
        super(holder);
        
        this.handshakeService = handshakeService;
        this.serverCiphers = serverCiphers;
        this.serverKeys = serverKeys;
    }
    
    @Override
    protected void decrypt(ChannelHandlerContext ctx, ByteBuf input, List<Object> out) throws IOException {
        if (firstPacket) {
            if (input.readableBytes() < SessionId.SIZE + Protocol.DATA_LENGTH_SIZE + Protocol.RANDOM_DATA_LENGTH_SIZE) {
                return;
            }
            
            byte[] sessionId = new byte[SessionId.SIZE];
            input.readBytes(sessionId);

            SessionData data = handshakeService.getServerSession(sessionId);
            if (!handshakeService.checkServerSession(sessionId)) {
                log.error("Wrong session signature! {} Channel: {}. Trying to re-handshake...", ByteBufUtil.hexDump(sessionId), ctx.channel());
                handshakeService.connect();
                handshakeService.close(ctx);
                return;
            }
            
            firstPacket = false;

            holder.setDecoderCiphers(serverCiphers, data.getIvData(), serverKeys);

            ByteBuf output = ctx.alloc().buffer(input.readableBytes());
            
            holder.decrypt(new ByteBufOutputStream(output), new ByteBufInputStream(input), Protocol.DATA_LENGTH_SIZE + Protocol.RANDOM_DATA_LENGTH_SIZE);
            
            if (!decrypt(ctx, input, output)) {
                return;
            }
            
            out.add(output);
            return;
        }
        
        super.decrypt(ctx, input, out);
    }
    
}
