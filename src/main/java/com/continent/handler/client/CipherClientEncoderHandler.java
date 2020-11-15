package com.continent.handler.client;

import com.continent.handler.CipherEncoderHandler;
import com.continent.random.RandomDelegator;
import com.continent.service.CryptoService;
import com.continent.service.Protocol;
import com.continent.service.SessionId;
import io.netty.buffer.ByteBuf;

public class CipherClientEncoderHandler extends CipherEncoderHandler {

    public static final byte SOCKS5_TUNNEL = 1;
    public static final byte PORT_MAPPING_TUNNEL = 2;
    
    private final String mappedHost;
    
    public CipherClientEncoderHandler(RandomDelegator randomGenerator,
                                      byte[] sessionId, String mappedHost, CryptoService holder) {
        super(randomGenerator, sessionId, holder);
        
        this.mappedHost = mappedHost;
    }
    
    @Override
    protected int encodeFirstHeader(ByteBuf buf) {
        if (mappedHost != null) {
            buf.writeByte(PORT_MAPPING_TUNNEL);
            byte[] mappedHostBytes = mappedHost.getBytes();
            buf.writeByte(mappedHostBytes.length);
            buf.writeBytes(mappedHostBytes);
            return SessionId.SIZE + Protocol.TUNNEL_TYPE_SIZE + mappedHostBytes.length + Protocol.DATA_LENGTH_SIZE + Protocol.RANDOM_DATA_LENGTH_SIZE;
        } else {
            buf.writeByte(SOCKS5_TUNNEL);
            return SessionId.SIZE + Protocol.TUNNEL_TYPE_SIZE + Protocol.DATA_LENGTH_SIZE + Protocol.RANDOM_DATA_LENGTH_SIZE;
        }
    }

}
