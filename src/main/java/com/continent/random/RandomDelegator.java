package com.continent.random;

import java.security.SecureRandom;

import org.bouncycastle.crypto.prng.RandomGenerator;

public class RandomDelegator extends SecureRandom implements RandomGenerator {
    
    private static final long serialVersionUID = 1L;
    
    // to solve NPE during Random class constructor invocation
    private final boolean init;
    private final RandomGenerator randomGenerator;

    public RandomDelegator(RandomGenerator randomGenerator) {
        super();
        this.init = true;
        this.randomGenerator = randomGenerator;
    }
    
    @Override
    public void setSeed(byte[] seed) {
        if (init) {
            randomGenerator.addSeedMaterial(seed);
        }
    }
    
    @Override
    public void setSeed(long seed) {
        if (init) {
            randomGenerator.addSeedMaterial(seed);
        }
    }
    
    @Override
    public void nextBytes(byte[] bytes) {
        randomGenerator.nextBytes(bytes);
    }

    @Override
    public void addSeedMaterial(byte[] seed) {
        randomGenerator.addSeedMaterial(seed);
    }

    @Override
    public void addSeedMaterial(long seed) {
        randomGenerator.addSeedMaterial(seed);
    }

    @Override
    public void nextBytes(byte[] bytes, int start, int len) {
        randomGenerator.nextBytes(bytes, start, len);
    }

}
