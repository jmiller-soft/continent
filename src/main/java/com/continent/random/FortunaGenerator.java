package com.continent.random;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;

import com.continent.engine.TwofishEngine;
import com.continent.engine.rc6.RC6_128Engine;
import com.continent.engine.rc6.RC6_256_256Engine;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SkeinDigest;
import org.bouncycastle.crypto.engines.CAST6Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.prng.RandomGenerator;

public class FortunaGenerator implements RandomGenerator {

    private class Generator {
        
        private final BlockCipher cipher; 
        private final Digest hash;
        private final byte[] counter;
        private final byte[] key;
        
        public Generator(BlockCipher cipher, Digest hash) {
            super();
            this.cipher = cipher;
            this.hash = hash;
            this.counter = new byte[cipher.getBlockSize()];
            this.key = new byte[32];
        }

        public void reseed(byte[] seed, int offset, int length) {
            hash.update(key, 0, key.length);
            hash.update(seed, offset, length);
            hash.doFinal(key, 0);
            
            cipher.reset();
            cipher.init(true, new KeyParameter(key));
            incrementCounter();
        }
        
        private void generateBlocks(byte[] data, int offset, int length) {
            for (int i = 0; i + cipher.getBlockSize() <= length; i += cipher.getBlockSize()) {
                cipher.processBlock(counter, 0, data, offset + i);
                incrementCounter();
            }
            
            int lastBlockSize = length & (cipher.getBlockSize()-1);
            if (lastBlockSize != 0) {
                byte[] block = new byte[cipher.getBlockSize()];
                cipher.processBlock(counter, 0, block, 0);
                incrementCounter();
                System.arraycopy(block, 0, data, length - lastBlockSize, lastBlockSize);
                burn(block);
            }
        }
        
        public void pseudoRandomData(byte[] data, int offset, int length) {
            if (cipher.getBlockSize() < 32 && length > 1024*1024) {
                throw new IllegalArgumentException("Requested random data amount exceed limit in 1MB");
            }
            
            generateBlocks(data, offset, length);
            
            // Switch to a new key to avoid later compromises of this output.
            generateBlocks(key, 0, key.length);
            cipher.reset();
            cipher.init(true, new KeyParameter(key));
        }

        private void incrementCounter() {
            for (int i = 0; i < counter.length; i++) {
                counter[i]++;
                if (counter[i] != 0)
                    break;
            }
        }
        
    }
    
    private static final int MIN_POOL_SIZE = 64;
    private final Digest[] pools = new Digest[32];
    private final Generator generator;

    private long lastReseedTime = 0;
    private long reseedCount = 0;
    private long pool0Count = 0;
    private int poolIndex = 0;
    
    public static void main(String[] args) throws InterruptedException, IOException {
        long t = System.currentTimeMillis();
        FortunaGenerator fortuna = new FortunaGenerator(new byte[] {3, 2, 1});
        byte[] out = new byte[1024*1024*10];
        fortuna.nextBytes(out);
        
        SeekableByteChannel f = Files.newByteChannel(Paths.get("C://out34.rnd"), StandardOpenOption.CREATE, StandardOpenOption.WRITE);
        ByteBuffer src = ByteBuffer.wrap(out);
        f.write(src);
        f.close();
        System.out.println(System.currentTimeMillis() - t);
    }
    
    public FortunaGenerator(byte[] seed) {
        // start from index = 1 since byte at index = 0 is used to select cipher   
        this(seed, selectCipher(seed), 1, seed.length-1);
    }

    public FortunaGenerator(byte[] seed, BlockCipher cipher) {
        this(seed, cipher, 0, seed.length);
    }
    
    FortunaGenerator(byte[] seed, BlockCipher cipher, int offset, int length) {
        for (int i = 0; i < pools.length; i++) {
            pools[i] = new SkeinDigest(SkeinDigest.SKEIN_256, 256);
        }
        
        generator = new Generator(cipher, new SkeinDigest(SkeinDigest.SKEIN_256, 256));
        generator.reseed(seed, offset, length);
    }
    
    private static BlockCipher selectCipher(byte[] seed) {
        BlockCipher[] ciphers = new BlockCipher[] {
                new TwofishEngine(24),
                new CAST6Engine(),
                new RC6_128Engine(30),
                new RC6_128Engine(34),
                new RC6_128Engine(38),
                new RC6_256_256Engine(30),
                new RC6_256_256Engine(34),
                new RC6_256_256Engine(38),
        };
        
        int index = Math.abs(seed[0] % ciphers.length);
        return ciphers[index];
    }
    
    public synchronized void addSeedMaterial(byte[] seed, int offset, int length) {
        pools[poolIndex].update(seed, offset, length);
        if (poolIndex == 0) {
            pool0Count += length;
        }
        poolIndex = (poolIndex + 1) % pools.length;
    }
    
    @Override
    public synchronized void addSeedMaterial(byte[] seed) {
        addSeedMaterial(seed, 0, seed.length);
    }

    @Override
    public synchronized void addSeedMaterial(long seed) {
        pools[poolIndex].update((byte)(seed & 0xff));
        pools[poolIndex].update((byte)((seed >>  8) & 0xff));
        pools[poolIndex].update((byte)((seed >> 16) & 0xff));
        pools[poolIndex].update((byte)((seed >> 24) & 0xff));
        pools[poolIndex].update((byte)((seed >> 32) & 0xff));
        pools[poolIndex].update((byte)((seed >> 40) & 0xff));
        pools[poolIndex].update((byte)((seed >> 48) & 0xff));
        pools[poolIndex].update((byte)((seed >> 56) & 0xff));
        if (poolIndex == 0) {
            pool0Count += 8;
        }
        poolIndex = (poolIndex + 1) % pools.length;
    }

    @Override
    public void nextBytes(byte[] bytes) {
        nextBytes(bytes, 0, bytes.length);
    }

    @Override
    public synchronized void nextBytes(byte[] bytes, int start, int len) {
        long now = System.currentTimeMillis();
        
        if (pool0Count >= MIN_POOL_SIZE && now - lastReseedTime > 100) {
            reseedCount++;
            
            long powerOfTwo = 1;
            byte[] seed = new byte[pools.length * pools[0].getDigestSize()];
            int seedIndex = 0;
            for (Digest pool : pools) {
                if (reseedCount % powerOfTwo == 0) {
                    pool.doFinal(seed, seedIndex);
                    seedIndex += pool.getDigestSize();
                }
                powerOfTwo <<= 1;
            }
            
            generator.reseed(seed, 0, seedIndex);
            burn(seed);
            lastReseedTime = now;
            pool0Count = 0;
        }
        
        generator.pseudoRandomData(bytes, start, len);
    }
    
    private void burn(byte[] buffer) {
        Arrays.fill(buffer, (byte)0);
    }

}
