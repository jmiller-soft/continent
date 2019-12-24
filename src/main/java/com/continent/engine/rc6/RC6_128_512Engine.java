package com.continent.engine.rc6;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.KeyParameter;

public class RC6_128_512Engine extends RC6_128Engine {

    public RC6_128_512Engine() {
        _noRounds = 32;
    }
    
    @Override
    public void init(boolean forEncryption, CipherParameters params) {
        KeyParameter p = (KeyParameter)params;
        if (p.getKey().length*8 != 512) {
            throw new IllegalArgumentException("Key size should be exactly 256 bits");
        }
        super.init(forEncryption, params);
    }

    
    @Override
    public String getAlgorithmName() {
        return super.getAlgorithmName() + "-128-512";
    }

}
