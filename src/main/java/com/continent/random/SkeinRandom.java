package com.continent.random;

import org.bouncycastle.crypto.digests.SkeinDigest;
import org.bouncycastle.crypto.params.SkeinParameters;
import org.bouncycastle.crypto.prng.RandomGenerator;

public class SkeinRandom implements RandomGenerator {

    private final int stateSizeBits;
    private final byte[] state;
    private SkeinParameters parameters;
    
    public SkeinRandom(byte[] seed) {
        if (seed == null) {
            throw new NullPointerException();
        }
        this.stateSizeBits = SkeinDigest.SKEIN_512;
        this.state = new byte[stateSizeBits / 8];
        
        addSeedMaterial(seed);
    }
    
    public SkeinRandom(byte[] seed, SkeinParameters parameters, int stateSizeBits) {
        super();
        this.stateSizeBits = stateSizeBits;
        this.parameters = parameters;
        this.state = new byte[stateSizeBits / 8];
        
        if (seed != null) {
            addSeedMaterial(seed);
        }
    }

    @Override
    public void addSeedMaterial(byte[] seed) {
        SkeinDigest digest = new SkeinDigest(stateSizeBits, state.length*8);
        digest.init(parameters);
        digest.update(state, 0, state.length);
        digest.update(seed, 0, seed.length);
        digest.doFinal(state, 0);
    }

    @Override
    public void addSeedMaterial(long seed) {
        byte[] bytes = {(byte)(seed & 0xff), 
                        (byte)((seed >>  8) & 0xff), 
                        (byte)((seed >> 16) & 0xff),
                        (byte)((seed >> 24) & 0xff), 
                        (byte)((seed >> 32) & 0xff), 
                        (byte)((seed >> 40) & 0xff),
                        (byte)((seed >> 48) & 0xff), 
                        (byte)((seed >> 56) & 0xff)};
        addSeedMaterial(bytes);
    }

    @Override
    public void nextBytes(byte[] bytes) {
        nextBytes(bytes, 0, bytes.length);
    }

    @Override
    public void nextBytes(byte[] bytes, int start, int len) {
        SkeinDigest digest = new SkeinDigest(stateSizeBits, (state.length + len)*8);
        digest.init(parameters);
        digest.update(state, 0, state.length);
        byte[] out = new byte[digest.getDigestSize()];
        digest.doFinal(out, 0);
        System.arraycopy(out, 0, state, 0, state.length);
        System.arraycopy(out, state.length, bytes, start, len);
    }

}
