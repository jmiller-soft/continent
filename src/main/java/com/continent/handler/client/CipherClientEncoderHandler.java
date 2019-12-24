package com.continent.handler.client;

import com.continent.handler.CipherEncoderHandler;
import com.continent.random.XoShiRo256StarStarRandom;
import com.continent.service.CryptoService;
import io.netty.buffer.ByteBuf;

public class CipherClientEncoderHandler extends CipherEncoderHandler {

    public static final byte SOCKS5_TUNNEL = 1;
    public static final byte PORT_MAPPING_TUNNEL = 2;
    
    private final String mappedHost;
    
    public CipherClientEncoderHandler(XoShiRo256StarStarRandom randomService,
                                      byte[] sessionId, String mappedHost, CryptoService holder) {
        super(randomService, sessionId, holder);
        
        this.mappedHost = mappedHost;
    }
    
    @Override
    protected int encodeFirstHeader(ByteBuf buf) {
        if (mappedHost != null) {
            buf.writeByte(PORT_MAPPING_TUNNEL);
            byte[] mappedHostBytes = mappedHost.getBytes();
            buf.writeByte(mappedHostBytes.length);
            buf.writeBytes(mappedHostBytes);
            return CryptoService.MAX_IV_SIZE + CryptoService.MAC_ID_SIZE + CryptoService.TUNNEL_TYPE_SIZE + mappedHostBytes.length + CryptoService.DATA_LENGTH_SIZE + CryptoService.RANDOM_DATA_LENGTH_SIZE;
        } else {
            buf.writeByte(SOCKS5_TUNNEL);
            return CryptoService.MAX_IV_SIZE + CryptoService.MAC_ID_SIZE + CryptoService.TUNNEL_TYPE_SIZE + CryptoService.DATA_LENGTH_SIZE + CryptoService.RANDOM_DATA_LENGTH_SIZE;
        }
    }

}
