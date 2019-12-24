package com.continent.handler.server;

import com.continent.handler.CipherEncoderHandler;
import com.continent.random.XoShiRo256StarStarRandom;
import com.continent.service.CryptoService;
import io.netty.buffer.ByteBuf;

public class CipherServerEncoderHandler extends CipherEncoderHandler {
    
    public CipherServerEncoderHandler(XoShiRo256StarStarRandom randomService, byte[] sessionId, CryptoService holder) {
        super(randomService, sessionId, holder);
    }


    @Override
    protected int encodeFirstHeader(ByteBuf buf) {
        return CryptoService.MAX_IV_SIZE + CryptoService.MAC_ID_SIZE + CryptoService.DATA_LENGTH_SIZE + CryptoService.RANDOM_DATA_LENGTH_SIZE;
    }

}
