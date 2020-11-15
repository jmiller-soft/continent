package com.continent.random;

import com.continent.engine.skein.SkeinDigest;
import org.bouncycastle.crypto.params.SkeinParameters;
import org.bouncycastle.crypto.prng.RandomGenerator;

import java.util.Arrays;

public class SkeinRandom implements RandomGenerator {

    private final int stateSizeBits;
    private final byte[] state;
    private final SkeinParameters parameters;
    private final SkeinDigest stateDigest;
    private int rounds;

    public SkeinRandom(byte[] seed) {
        this(seed, null, SkeinDigest.SKEIN_512, 72);
    }

    public SkeinRandom(byte[] seed, int rounds) {
        this(seed, null, SkeinDigest.SKEIN_512, rounds);
    }

    public SkeinRandom(byte[] seed, SkeinParameters parameters, int stateSizeBits, int rounds) {
        super();
        this.stateSizeBits = stateSizeBits;
        this.parameters = parameters;
        this.state = new byte[stateSizeBits / 8];
        stateDigest = new SkeinDigest(stateSizeBits, stateSizeBits, rounds);
        stateDigest.init(parameters);
        this.rounds = rounds;

        if (seed != null) {
            addSeedMaterial(seed);
        }
    }

    @Override
    public synchronized void addSeedMaterial(byte[] seed) {
        stateDigest.update(state, 0, state.length);
        stateDigest.update(seed, 0, seed.length);
        stateDigest.doFinal(state, 0);
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
    public synchronized void nextBytes(byte[] bytes, int start, int len) {
        SkeinDigest digest = new SkeinDigest(stateSizeBits, (state.length + len)*8, rounds);
        digest.init(parameters);
        digest.update(state, 0, state.length);
        byte[] out = new byte[digest.getDigestSize()];
        digest.doFinal(out, 0);
        System.arraycopy(out, 0, state, 0, state.length);
        System.arraycopy(out, state.length, bytes, start, len);
        Arrays.fill(out, (byte)0);
    }

}
