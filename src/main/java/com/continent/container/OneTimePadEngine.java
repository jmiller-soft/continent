package com.continent.container;

import com.continent.random.OneTimePadGenerator;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.StreamCipher;

public class OneTimePadEngine implements StreamCipher {

    private final OneTimePadGenerator generator;
    private final byte[] buf;
    private int bufIndex;

    public OneTimePadEngine(OneTimePadGenerator generator, int bufferSize) {
        super();
        this.generator = generator;
        this.buf = new byte[bufferSize];
        bufIndex = buf.length;
    }

    @Override
    public void init(boolean forEncryption, CipherParameters params) throws IllegalArgumentException {
        throw new UnsupportedOperationException();
    }

    @Override
    public String getAlgorithmName() {
        return "OneTimePadEngine";
    }

    @Override
    public byte returnByte(byte in) {
        if (bufIndex == buf.length) {
            generator.nextBytes(buf);
            bufIndex = 0;
        }

        byte res = (byte)((buf[bufIndex] ^ in) & 0xFF);
        bufIndex++;
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
