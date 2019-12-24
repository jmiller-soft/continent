package com.continent.random;

import org.bouncycastle.crypto.prng.RandomGenerator;

public class SkeinRandomTest extends BaseRandomTest {

    @Override
    RandomGenerator createRandom(byte[] seed) {
        return new SkeinRandom(seed);
    }

    
}
