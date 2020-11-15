package com.continent.engine;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.StreamCipher;

import java.io.IOException;
import java.io.InputStream;

public class XorFileEngine implements StreamCipher {

    private final InputStream inputStream;

    public XorFileEngine(InputStream inputStream) {
        super();
        this.inputStream = inputStream;
    }

    @Override
    public void init(boolean forEncryption, CipherParameters params) throws IllegalArgumentException {
        throw new UnsupportedOperationException();
    }

    @Override
    public String getAlgorithmName() {
        return "XorFileEngine";
    }

    @Override
    public byte returnByte(byte in) {
        try {
            byte key = (byte)inputStream.read();
            if (key == -1) {
                return -1;
            }
            return (byte)((key ^ in) & 0xFF);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public int processBytes(byte[] in, int inOff, int len, byte[] out, int outOff) throws DataLengthException {
        try {
            int res = inputStream.read(out, outOff, len);
            if (res == -1) {
                return -1;
            }
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }

        for (int i = 0; i < len; i++) {
            out[outOff + i] = (byte) ((in[inOff + i] ^ out[outOff + i]) & 0xFF);
        }
        return len;
    }

    @Override
    public void reset() {
        throw new UnsupportedOperationException();
    }

}
