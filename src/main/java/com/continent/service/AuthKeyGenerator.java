package com.continent.service;

import com.continent.random.FortunaGenerator;
import com.continent.random.RandomDelegator;
import com.continent.random.entropy.JitterEntropy;
import com.google.common.io.BaseEncoding;
import net.sf.ntru.encrypt.EncryptionKeyPair;

import java.nio.ByteBuffer;

public class AuthKeyGenerator {

    public void init() {
        JitterEntropy entropy = new JitterEntropy();
        ByteBuffer seed = ByteBuffer.allocate(32);
        entropy.fill(seed);
        FortunaGenerator random = new FortunaGenerator(seed.array());
        EncryptionKeyPair e = CryptoService.NTRU.generateKeyPair(new RandomDelegator(random), true);

        String pub = BaseEncoding.base64().encode(e.getPublic().getEncoded());
        String priv = BaseEncoding.base64().encode(e.getPrivate().getEncoded());

        byte[] id = new byte[18];
        random.nextBytes(id);
        String encodedId = BaseEncoding.base64().encode(id);
        String encodedSeed = BaseEncoding.base64().encode(seed.array());
        
        System.out.println("Client key: " + encodedId + ":" + encodedSeed);
        System.out.println("Server key: " + encodedId + ":" + pub);
    }

    
}
