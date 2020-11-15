package com.continent.random;

import com.continent.random.entropy.NativeJitterEntropy;
import org.bouncycastle.crypto.prng.RandomGenerator;

import java.nio.ByteBuffer;

public class NativeJitterGenerator implements RandomGenerator {

    private final NativeJitterEntropy e = new NativeJitterEntropy();

    @Override
    public void addSeedMaterial(byte[] seed) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void addSeedMaterial(long seed) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void nextBytes(byte[] bytes) {
        nextBytes(bytes, 0, bytes.length);
    }

    @Override
    public void nextBytes(byte[] bytes, int start, int len) {
        ByteBuffer b = ByteBuffer.wrap(bytes, start, len);
        e.fill(b);
    }

    public void shutdown() {
        e.shutdown();
    }

}
