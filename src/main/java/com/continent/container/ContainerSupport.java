package com.continent.container;

import com.continent.engine.*;
import com.continent.engine.rc6.RC6_256_1024Engine;
import com.continent.engine.rc6.RC6_256_2048Engine;
import com.continent.engine.rc6.RC6_256_256Engine;
import com.continent.engine.rc6.RC6_256_512Engine;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.crypto.digests.SkeinDigest;
import org.bouncycastle.crypto.engines.CAST6Engine;
import org.bouncycastle.crypto.engines.HC256Engine;
import org.bouncycastle.crypto.engines.SerpentEngine;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.*;

public class ContainerSupport {

    // 4 NTRU chunks by 247 bytes are enough to encrypt 768 bytes of key data
    public static final int ntruChunks = 4;

    public static byte[] HEADER = {0x18, 0x32, 0x71, 0x35};

    public static final int BUFFER_SIZE = 8192;

    public static final int saltSize = 256;
    public static final int ivSize = 128 + 128 + 128;
    public static final int randomTailBytesLimit = 1024;

    public static final Map<String, Class<?>> CIPHERS = new HashMap<>();
    static  {
        CIPHERS.put("a", TwofishEngine.class);
        CIPHERS.put("b", SerpentEngine.class);
        CIPHERS.put("c", CAST6Engine.class);

        CIPHERS.put("d", RC6_256_256Engine.class);
        CIPHERS.put("e", RC6_256_512Engine.class);
        CIPHERS.put("f", RC6_256_1024Engine.class);
        CIPHERS.put("g", RC6_256_2048Engine.class);

        CIPHERS.put("h", Threefish256Engine.class);
        CIPHERS.put("i", Threefish512Engine.class);
        CIPHERS.put("j", Threefish1024Engine.class);

        CIPHERS.put("k", HC256Engine.class);

        CIPHERS.put("l", SkeinStream256Engine.class);
        CIPHERS.put("m", SkeinStream512Engine.class);
        CIPHERS.put("n", SkeinStream1024Engine.class);
    }

    // 3 ciphers up to 256 bits
    static final int maxKeySize = 768;

    void burn(byte[] buffer) {
        Arrays.fill(buffer, (byte)0);
    }

    String getCipherName(List<Object> ciphers) {
        StringBuilder s = new StringBuilder();
        for (Object cipher : ciphers) {
            if (cipher instanceof Class) {
                s.append(((Class)cipher).getSimpleName() + ", ");
            }
            if (cipher instanceof BlockCipher) {
                s.append(((BlockCipher)cipher).getAlgorithmName() + ", ");
            }
            if (cipher instanceof StreamCipher) {
                s.append(((StreamCipher)cipher).getAlgorithmName() + ", ");
            }
        }
        return s.toString();
    }

    long copy(InputStream source, OutputStream sink) throws IOException {
        long nread = 0L;
        byte[] buf = new byte[BUFFER_SIZE];
        int n;
        while ((n = source.read(buf)) > 0) {
            sink.write(buf, 0, n);
            nread += n;
        }
        return nread;
    }



}
