package com.continent.container;

import com.continent.engine.skein.SkeinDigest;

public class SkeinKeyGenerator implements KeyGenerator {

    private int stateSizeBits;

    public SkeinKeyGenerator(int stateSizeBits) {
        this.stateSizeBits = stateSizeBits;
    }

    @Override
    public byte[] generateKeyData(byte[] password, byte[] salt, int keySize, int pim) {
        byte[] key = new byte[keySize];
        SkeinDigest digest = new SkeinDigest(stateSizeBits, key.length*8, pim*1024*1024);
        digest.update(salt, 0, salt.length);
        digest.update(password, 0, password.length);
        digest.doFinal(key, 0);
        return key;
    }

}
