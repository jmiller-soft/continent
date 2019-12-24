package com.continent.engine.rc6;

import java.math.BigInteger;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * An RC6 engine.
 */
public class RC6_512_512Engine extends RC6_NEngine {
    
    private static final BigInteger P64 = new BigInteger("b7e151628aed2a6abf7158809cf4f3c7", 16);
    private static final BigInteger Q64 = new BigInteger("9e3779b97f4a7c15f39cc0605cedc834", 16);
    private static final BigInteger LGW = BigInteger.valueOf(7);          // log2(128)
    private static final int rounds = 32;
    private static final int wordSize = 128;
    
    public RC6_512_512Engine() {
        super(rounds, wordSize, P64, Q64, LGW);
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
        return super.getAlgorithmName() + "-512-512";
    }
    
}
