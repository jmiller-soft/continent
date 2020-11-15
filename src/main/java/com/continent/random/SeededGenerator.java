package com.continent.random;

import com.continent.random.entropy.NativeJitterEntropy;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import org.bouncycastle.crypto.prng.RandomGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class SeededGenerator implements RandomGenerator {

    private final Logger log = LoggerFactory.getLogger(SeededGenerator.class);

    private final NativeJitterEntropy e = new NativeJitterEntropy();
    private final SkeinRandom random;
    private final ScheduledExecutorService ee = Executors.newScheduledThreadPool(1);

    public SeededGenerator(SkeinRandom r, int initSeedSize, final int seedSize, int timeIntervalInMs) {
        this.random = r;
        ByteBuffer initBuf = ByteBuffer.allocate(initSeedSize);
        e.fill(initBuf);

        if (log.isDebugEnabled()) {
            log.debug("start seed ({}):\n{}", initBuf.array().length, prettyDump(initBuf.array()));
        }

        random.addSeedMaterial(initBuf.array());
        Arrays.fill(initBuf.array(), (byte)0);

        if (timeIntervalInMs == 0) {
            ee.submit(new Runnable() {
                @Override
                public void run() {
                    try {
                        ByteBuffer buf = ByteBuffer.allocate(seedSize);
                        while (!Thread.currentThread().isInterrupted()) {
                            e.fill(buf);

                            if (log.isDebugEnabled()) {
                                log.debug("added seed ({}):\n{}", buf.array().length, prettyDump(buf.array()));
                            }

                            random.addSeedMaterial(buf.array());
                            buf.clear();
                        }
                        Arrays.fill(buf.array(), (byte)0);
                    } catch (Exception ex) {
                        ex.printStackTrace();
                    }
                }
            });
        } else {
            final ByteBuffer buf = ByteBuffer.allocate(seedSize);
            ee.scheduleWithFixedDelay(new Runnable() {
                @Override
                public void run() {
                    try {
                        e.fill(buf);

                        if (log.isDebugEnabled()) {
                            log.debug("added seed ({}):\n{}", buf.array().length, prettyDump(buf.array()));
                        }

                        random.addSeedMaterial(buf.array());
                        buf.clear();
                        Arrays.fill(buf.array(), (byte)0);
                    } catch (Exception ex) {
                        ex.printStackTrace();
                    }
                }
            }, timeIntervalInMs, timeIntervalInMs, TimeUnit.MILLISECONDS);
        }
    }

    private String prettyDump(byte[] seedBytes) {
        return ByteBufUtil.prettyHexDump(Unpooled.wrappedBuffer(seedBytes));
    }

    @Override
    public void addSeedMaterial(byte[] seed) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void addSeedMaterial(long seed) {
        throw new UnsupportedOperationException();
    }

    public void nextBytes(byte[] bytes) {
        random.nextBytes(bytes);
    }

    @Override
    public void nextBytes(byte[] bytes, int start, int len) {
        random.nextBytes(bytes, start, len);
    }

    public void shutdown() {
        ee.shutdownNow();
        e.shutdown();
    }

}
