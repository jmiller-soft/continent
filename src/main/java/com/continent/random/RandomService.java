package com.continent.random;

import com.continent.engine.skein.SkeinDigest;
import com.continent.random.entropy.EntropySource;
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

public class RandomService {

    private static final Logger log = LoggerFactory.getLogger(RandomService.class);

    private final ScheduledExecutorService executor = Executors.newScheduledThreadPool(2);

    private final RandomDelegator keyGenerator;
    private final RandomDelegator nonceGenerator;

    private final EntropySource keySeedSource;
    private final EntropySource nonceSeedSource;
    
    public RandomService(int nonceSeedInterval, int keySeedInterval) {
        this(new NativeJitterEntropy(), new NativeJitterEntropy(), nonceSeedInterval, keySeedInterval);
    }

    public RandomService(final EntropySource keySeedSource, final EntropySource nonceSeedSource, int nonceSeedInterval, int keySeedInterval) {
        this.keySeedSource = keySeedSource;
        this.nonceSeedSource = nonceSeedSource;

        nonceGenerator = createGenerator(nonceSeedSource, 128);
        keyGenerator = createGenerator(keySeedSource, 256);

        if (nonceSeedInterval == 0) {
            nonceSeedInterval = 60;
        }
        if (keySeedInterval == 0) {
            keySeedInterval = 30;
        }

        // seed every second
        final ByteBuffer nonceSeedBuffer = ByteBuffer.allocate(8);
        executor.scheduleWithFixedDelay(new Runnable() {
            @Override
            public void run() {
            addSeed(nonceGenerator, nonceSeedSource, nonceSeedBuffer);
            }
        }, nonceSeedInterval, nonceSeedInterval, TimeUnit.SECONDS);

        final ByteBuffer keySeedBuffer = ByteBuffer.allocate(16);
        executor.scheduleWithFixedDelay(new Runnable() {
            @Override
            public void run() {
            addSeed(keyGenerator, keySeedSource, keySeedBuffer);
            }
        }, keySeedInterval, keySeedInterval, TimeUnit.SECONDS);
    }

    private RandomDelegator createGenerator(EntropySource seedSource, int seedSize) {
        ByteBuffer seedBytes = ByteBuffer.allocate(seedSize);
        seedSource.fill(seedBytes);
        if (seedBytes.hasRemaining()) {
            throw new IllegalStateException("Seed buffer hasn't been fulfilled");
        }
        seedBytes.flip();
        try {
            return createGenerator(seedBytes);
        } finally {
            burn(seedBytes);
        }
    }

    public RandomDelegator getKeyGenerator() {
        return keyGenerator;
    }
    
    public RandomDelegator getNonceGenerator() {
        return nonceGenerator;
    }

    public RandomDelegator createRandomDataGenerator() {
        byte[] startSeed = new byte[64];
        getNonceGenerator().nextBytes(startSeed);
        if (log.isDebugEnabled()) {
            log.debug("random data generator seed ({}):\n{}", startSeed.length, prettyDump(startSeed));
        }

        RandomGenerator randomGenerator = new SkeinRandom(startSeed, null, SkeinDigest.SKEIN_256, 16);
        burn(startSeed);
        return new RandomDelegator(randomGenerator);
    }

    private String prettyDump(byte[] seedBytes) {
        return ByteBufUtil.prettyHexDump(Unpooled.wrappedBuffer(seedBytes));
    }

    /**
     * Creates random generator.
     * Splits seed data into start seed and initial seed data.
     * 
     * @param seed - seed data.
     * @return random generator
     */
    private RandomDelegator createGenerator(ByteBuffer seed) {
        byte[] startSeed = new byte[seed.remaining()];
        seed.get(startSeed);

        if (log.isDebugEnabled()) {
            log.debug("init seed ({}):\n{}", startSeed.length, prettyDump(startSeed));
        }
        
        RandomGenerator randomGenerator = new SkeinRandom(startSeed);
        burn(startSeed);
        return new RandomDelegator(randomGenerator);
    }
    
    private void addSeed(RandomDelegator random, EntropySource seedSource, ByteBuffer newSeedBuffer) {
        newSeedBuffer.clear();
        seedSource.fill(newSeedBuffer);

        if (log.isDebugEnabled()) {
            log.debug("added seed ({}):\n{}", newSeedBuffer.array().length, prettyDump(newSeedBuffer.array()));
        }
        random.addSeedMaterial(newSeedBuffer.array());

        burn(newSeedBuffer);
    }

    public void shutdown() {
        executor.shutdownNow();
        keySeedSource.shutdown();
        nonceSeedSource.shutdown();
    }

    private static void burn(ByteBuffer buffer) {
        burn(buffer.array());
    }
    
    private static void burn(byte[] buf) {
        Arrays.fill(buf, (byte)0);
    }

    
}
