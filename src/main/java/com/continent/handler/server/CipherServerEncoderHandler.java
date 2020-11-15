package com.continent.handler.server;

import com.continent.handler.CipherEncoderHandler;
import com.continent.random.RandomDelegator;
import com.continent.service.CryptoService;
import com.continent.service.Protocol;
import com.continent.service.SessionId;
import io.netty.buffer.ByteBuf;

public class CipherServerEncoderHandler extends CipherEncoderHandler {
    
    public CipherServerEncoderHandler(RandomDelegator randomGenerator, byte[] sessionId, CryptoService holder) {
        super(randomGenerator, sessionId, holder);
    }

    @Override
    protected int encodeFirstHeader(ByteBuf buf) {
        return SessionId.SIZE + Protocol.DATA_LENGTH_SIZE + Protocol.RANDOM_DATA_LENGTH_SIZE;
    }

}
