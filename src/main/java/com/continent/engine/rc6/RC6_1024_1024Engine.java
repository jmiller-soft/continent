package com.continent.engine.rc6;

import java.math.BigInteger;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * An RC6 engine.
 */
public class RC6_1024_1024Engine extends RC6_NEngine {
    
    private static final BigInteger P64 = new BigInteger("b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef", 16);
    private static final BigInteger Q64 = new BigInteger("9e3779b97f4a7c15f39cc0605cedc8341082276bf3a27251f86c6a11d0c18e95", 16);
    private static final BigInteger LGW = BigInteger.valueOf(8);          // log2(256)
    private static final int rounds = 40;
    private static final int wordSize = 256;
    
    public RC6_1024_1024Engine() {
        super(rounds, wordSize, P64, Q64, LGW);
    }
    
    @Override
    public void init(boolean forEncryption, CipherParameters params) {
        KeyParameter p = (KeyParameter)params;
        if (p.getKey().length*8 != 1024) {
            throw new IllegalArgumentException("Key size should be exactly 1024 bits");
        }
        super.init(forEncryption, params);
    }
 
    @Override
    public String getAlgorithmName() {
        return super.getAlgorithmName() + "-1024-1024";
    }
    
}
