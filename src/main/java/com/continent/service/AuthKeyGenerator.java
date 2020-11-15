package com.continent.service;

import com.continent.engine.skein.SkeinDigest;
import com.continent.random.FortunaGenerator;
import com.continent.random.RandomDelegator;
import com.continent.random.SkeinRandom;
import com.continent.random.entropy.NativeJitterEntropy;
import com.google.common.io.BaseEncoding;
import net.sf.ntru.encrypt.EncryptionKeyPair;

import java.nio.ByteBuffer;

public class AuthKeyGenerator {

    public void init() {
        NativeJitterEntropy entropy = new NativeJitterEntropy();
        ByteBuffer seed = ByteBuffer.allocate(32);
        entropy.fill(seed);
        SkeinRandom random = new SkeinRandom(seed.array(), null, SkeinDigest.SKEIN_256, 72);
        EncryptionKeyPair e = CryptoService.NTRU.generateKeyPair(new RandomDelegator(random), false);

        String pub = BaseEncoding.base64().encode(e.getPublic().getEncoded());
        String priv = BaseEncoding.base64().encode(e.getPrivate().getEncoded());

        byte[] id = new byte[18];
        random.nextBytes(id);
        String encodedId = BaseEncoding.base64().encode(id);
        String encodedSeed = BaseEncoding.base64().encode(seed.array());

        entropy.shutdown();

        System.out.println("Client key: " + encodedId + ":" + encodedSeed);
        System.out.println("Server key: " + encodedId + ":" + pub);
    }

    
}
