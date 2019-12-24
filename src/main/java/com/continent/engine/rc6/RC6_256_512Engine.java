package com.continent.engine.rc6;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * An RC6 engine.
 */
public class RC6_256_512Engine extends RC6_256Engine {
    
    public RC6_256_512Engine() {
        super(38);
    }
    
    @Override
    public void init(boolean forEncryption, CipherParameters params) {
        KeyParameter p = (KeyParameter)params;
        if (p.getKey().length*8 != 512) {
            throw new IllegalArgumentException("Key size should be exactly 512 bits");
        }
        super.init(forEncryption, params);
    }
 
    @Override
    public String getAlgorithmName() {
        return super.getAlgorithmName() + "-256-512";
    }
    
}
