package com.continent.random;

import com.continent.random.entropy.NativeJitterEntropy;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class OneTimePadGenerator {

    private final NativeJitterEntropy e = new NativeJitterEntropy();
    private final SkeinRandom random;
    private final ExecutorService ee = Executors.newFixedThreadPool(1);

    public OneTimePadGenerator(SkeinRandom r) {
        this.random = r;
        ByteBuffer initBuf = ByteBuffer.allocate(512);
        e.fill(initBuf);
        random.addSeedMaterial(initBuf.array());
        Arrays.fill(initBuf.array(), (byte)0);

        ee.submit(new Runnable() {
            @Override
            public void run() {
                try {
                    ByteBuffer buf = ByteBuffer.allocate(8);
                    while (!Thread.currentThread().isInterrupted()) {
                        e.fill(buf);
                        random.addSeedMaterial(buf.array());
                        buf.clear();
                    }
                    Arrays.fill(buf.array(), (byte)0);
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
            }
        });
    }

    public void nextBytes(byte[] bytes) {
        random.nextBytes(bytes);
    }

    public void shutdown() {
        ee.shutdownNow();
        e.shutdown();
    }

}
