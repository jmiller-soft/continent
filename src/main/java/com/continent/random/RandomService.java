package com.continent.random;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.crypto.prng.RandomGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.continent.random.entropy.EntropySource;
import com.continent.random.entropy.JitterEntropy;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;

public class RandomService {

    private static final Logger log = LoggerFactory.getLogger(RandomService.class);

    private static final int SEED_SIZE = 1024*4;

    private final ScheduledExecutorService executor = Executors.newScheduledThreadPool(2);

    private final RandomDelegator keyGenerator;
    private final RandomDelegator nonceGenerator;
    
    public RandomService() {
        this(new JitterEntropy(), new JitterEntropy());
    }
    
    public RandomService(final EntropySource keySeedSource, final EntropySource nonceSeedSource) {
        nonceGenerator = createGenerator(nonceSeedSource, SEED_SIZE);
        keyGenerator = createGenerator(keySeedSource, SEED_SIZE);

        // add seed every second
        final ByteBuffer nonceSeedBuffer = ByteBuffer.allocate(8);
        executor.scheduleWithFixedDelay(new Runnable() {
            @Override
            public void run() {
                addSeed(nonceGenerator, nonceSeedSource, nonceSeedBuffer, 2);
            }
        }, 1, 1, TimeUnit.SECONDS);

        final ByteBuffer keySeedBuffer = ByteBuffer.allocate(8);
        executor.scheduleWithFixedDelay(new Runnable() {
            @Override
            public void run() {
                addSeed(keyGenerator, keySeedSource, keySeedBuffer, 2);
            }
        }, 1, 1, TimeUnit.SECONDS);

        log.info("Random generators are ready");
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
        byte[] startSeed = new byte[seed.remaining()/2];
        seed.get(startSeed);

        if (log.isDebugEnabled()) {
            log.debug("startSeed ({}):\n{}", startSeed.length, prettyDump(startSeed));
        }
        
        RandomGenerator fortuna = new FortunaGenerator(startSeed);
        burn(startSeed);
        addSeedMaterial(seed, fortuna);
        return new RandomDelegator(fortuna);
    }
    
    private void addSeedMaterial(final ByteBuffer seedBytes, RandomGenerator fortuna) {
        byte[] out = new byte[1024];
        fortuna.nextBytes(out);
        burn(out);
        
        while (true) {
            int size = Math.min(64, seedBytes.remaining());
            byte[] material = new byte[size];
            seedBytes.get(material);
            
            if (log.isDebugEnabled()) {
                log.debug("initial seed ({}):\n{}", material.length, prettyDump(material));
            }
            
            fortuna.addSeedMaterial(material);
            burn(material);
            if (size < 64) {
                break;
            }
        }
        
        fortuna.nextBytes(out);
        burn(out);
        
        log.debug("Random seed material added");
    }
    
    private void addSeed(RandomDelegator fortuna, EntropySource seedSource, ByteBuffer newSeedBuffer, int loops) {
        for (int i = 0; i < loops; i++) {
            newSeedBuffer.clear();
            seedSource.fill(newSeedBuffer);
            fortuna.addSeedMaterial(newSeedBuffer.array());
            
            if (log.isDebugEnabled()) {
                log.debug("seed added ({}):\n{}", newSeedBuffer.array().length, prettyDump(newSeedBuffer.array()));
            }
            
            burn(newSeedBuffer);
        }
    }

    public void shutdown() {
        executor.shutdown();
    }

    private static void burn(ByteBuffer buffer) {
        burn(buffer.array());
    }
    
    private static void burn(byte[] buf) {
        Arrays.fill(buf, (byte)0);
    }

    
}
