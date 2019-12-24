package com.continent.handler.client;

import java.util.List;

import com.continent.handler.CipherDecoderHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.continent.service.CryptoService;
import com.continent.service.HandshakeService;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;

public class CipherClientDecoderHandler extends CipherDecoderHandler {

    private static final Logger log = LoggerFactory.getLogger(CipherClientDecoderHandler.class);
    
    private final HandshakeService handshakeService;
    private final byte[] sessionId;
    private final List<Object> serverCiphers;
    private final byte[] serverKeys;

    private boolean firstPacket = true;
    
    public CipherClientDecoderHandler(HandshakeService handshakeService, CryptoService holder, byte[] sessionId, List<Object> serverCiphers, byte[] serverKeys) {
        super(holder);
        
        this.handshakeService = handshakeService;
        this.sessionId = sessionId;
        this.serverCiphers = serverCiphers;
        this.serverKeys = serverKeys;
    }
    
    @Override
    protected void decrypt(ChannelHandlerContext ctx, ByteBuf input, List<Object> out) {
        if (firstPacket) {
            if (input.readableBytes() < CryptoService.MAX_IV_SIZE + CryptoService.MAC_ID_SIZE + CryptoService.DATA_LENGTH_SIZE + CryptoService.RANDOM_DATA_LENGTH_SIZE) {
                return;
            }
            
            input.markReaderIndex();
            
            byte[] sessionMac = holder.checkSessionMac(input, sessionId);
            if (sessionMac == null) {
                log.error("Wrong session signature! Channel: {}. Trying to re-handshake...", ctx.channel());
                handshakeService.connect();
                handshakeService.close(ctx);
                return;
            }
            
            firstPacket = false;
            
            input.resetReaderIndex();
            byte[] ivData = new byte[CryptoService.MAX_IV_SIZE];
            input.readBytes(ivData);
            input.skipBytes(CryptoService.MAC_ID_SIZE);
            
            holder.setDecoderCiphers(serverCiphers, ivData, serverKeys);
            
            ByteBuf output = ctx.alloc().buffer(input.readableBytes());
            
            holder.decrypt(output, input, CryptoService.DATA_LENGTH_SIZE + CryptoService.RANDOM_DATA_LENGTH_SIZE);
            
            if (!decrypt(ctx, input, output)) {
                return;
            }
            
            out.add(output);
            return;
        }
        
        super.decrypt(ctx, input, out);
    }
    
}
