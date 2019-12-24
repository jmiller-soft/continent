package com.continent.container;

import com.continent.service.CryptoService;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.util.Memoable;

import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

public class KeyGenerator {

    private byte[] password; 
    private byte[] salt;
    private List<Object> ciphers;
    private Digest digest;
    private int iterations;

    public KeyGenerator(byte[] password, byte[] salt, List<Object> ciphers, Digest digest, int iterations) {
        super();
        this.password = password;
        this.salt = salt;
        this.ciphers = ciphers;
        this.digest = digest;
        this.iterations = iterations;
    }

    public byte[] generateKeyData() {
        int keyDataSize = 0;
        for (Object blockCipher : ciphers) {
            if (blockCipher instanceof Class) {
                keyDataSize += CryptoService.CIPHER_KEY_SIZE.get(blockCipher);
            } else {
                keyDataSize += CryptoService.CIPHER_KEY_SIZE.get(blockCipher.getClass());
            }
        }
        
        int digestsAmount = keyDataSize / digest.getDigestSize();
        if (keyDataSize % digest.getDigestSize() != 0) {
            digestsAmount += 1;
        }
        
        final byte[][] keysMap = new byte[digestsAmount][];
        
        ExecutorService executor = Executors.newFixedThreadPool(Math.min(digestsAmount, Runtime.getRuntime().availableProcessors()));
        final AtomicInteger currentIterations = new AtomicInteger();
        final int totalIterations = digestsAmount * iterations;
        for (int k = 0; k < digestsAmount; k++) {
            final byte num = (byte) k;
            executor.execute(new Runnable() {
                @Override
                public void run() {
                    byte[] buffer = new byte[digest.getDigestSize()];

                    Digest d = (Digest) ((Memoable) digest).copy();
                    d.update(salt, 0, salt.length);
                    d.update(password, 0, password.length);
                    d.update(num);
                    d.doFinal(buffer, 0);

                    for (int i = 0; i < iterations; i++) {

                        synchronized (KeyGenerator.this) {
                            int progress = (int) (((double)currentIterations.incrementAndGet() * 100) / totalIterations);
                            System.out.print("\rGenerating key data (" + digest.getAlgorithmName() + ") - " + progress + "%");
                        }

                        d.update(buffer, 0, buffer.length);
                        d.doFinal(buffer, 0);
                    }

                    keysMap[num] = buffer;
                }
            });
        }
        
        executor.shutdown();
        try {
            executor.awaitTermination(10, TimeUnit.MINUTES);
        } catch (InterruptedException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        
        System.out.println();

        burn(password);

        byte[] result = join(keysMap);
        for (byte[] key : keysMap) {
            burn(key);
        }

        return result;
    }

    private byte[] join(byte[]... arrays) {
        int len = 0;
        for (byte[] bs : arrays) {
            len += bs.length;
        }
        byte[] joinedArray = new byte[len];
        int index = 0;
        for (byte[] bs : arrays) {
            System.arraycopy(bs, 0, joinedArray, index, bs.length);
            index += bs.length;
        }
        return joinedArray;
    }

    private void burn(byte[] buffer) {
        Arrays.fill(buffer, (byte)0);
    }
    
}
