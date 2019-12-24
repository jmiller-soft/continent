package com.continent.engine;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.prng.RandomGenerator;

import com.continent.random.SkeinRandom;

public class VernamEngine implements StreamCipher {

    private final RandomGenerator random;

    private boolean init;
    private int index;
    private byte[] key;
    
    public VernamEngine(RandomGenerator random) {
        super();
        this.random = random;
    }

    public static void main(String[] args) throws IOException {
        RandomGenerator r = new SkeinRandom(new byte[] {1, 2, 3, 4, 5, 6, 7});
//        RandomGenerator r = new FortunaGenerator(new byte[] {1, 2, 3, 4, 5, 6, 7});
        VernamEngine re = new VernamEngine(r);
        
        byte[] in = Files.readAllBytes(Paths.get("C:\\Devel\\projects\\crypto-proxy\\1"));
//        byte[] in = new byte[926900];
        byte[] out = new byte[in.length];
        
        re.processBytes(in, 0, in.length, out, 0);
        Files.write(Paths.get("C:\\Devel\\projects\\crypto-proxy\\skein-out3"), out, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
    }
    
    @Override
    public void init(boolean forEncryption, CipherParameters params) throws IllegalArgumentException {
        throw new UnsupportedOperationException();
    }

    @Override
    public String getAlgorithmName() {
        return "Vernam-" + random.getClass().getSimpleName();
    }

    @Override
    public byte returnByte(byte in) {
        if (!init || index == key.length) {
            init = true;
            index = 0;

            // generate random key length in range between 1 and 1024
            byte[] keyLength = new byte[2];
            random.nextBytes(keyLength);

            int length = keyLength[0] & 0xFF;
            length += (keyLength[1] & 0xFF) << 8;
            length = Math.abs(length) % 1023 + 1;
            
            key = new byte[length];
            random.nextBytes(key);
        }
        byte res = (byte)((key[index] ^ in) & 0xFF);
        // burn it
        key[index] = 0;
        index++;
        return res;
    }

    @Override
    public int processBytes(byte[] in, int inOff, int len, byte[] out, int outOff) throws DataLengthException {
        for (int i = 0; i < len; i++) {
            out[outOff + i] = returnByte(in[inOff + i]);
        }
        return len;
    }

    @Override
    public void reset() {
        throw new UnsupportedOperationException();
    }

}
