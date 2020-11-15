package com.continent.engine;

import java.util.List;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.StreamCipher;

public class CascadeStreamCipher implements StreamCipher {

    private final List<StreamCipher> ciphers;
    
    public CascadeStreamCipher(List<StreamCipher> ciphers) {
        super();
        this.ciphers = ciphers;
    }

    @Override
    public void init(boolean forEncryption, CipherParameters params) throws IllegalArgumentException {
        throw new UnsupportedOperationException();
    }

    @Override
    public String getAlgorithmName() {
        StringBuilder result = new StringBuilder();
        for (StreamCipher streamCipher : ciphers) {
            result.append(streamCipher.getAlgorithmName()).append(",");
        }
        return result.toString();
    }

    @Override
    public byte returnByte(byte in) {
        byte result = in;
        for (StreamCipher streamCipher : ciphers) {
            result = streamCipher.returnByte(result);
        }
        return result;
    }

    @Override
    public int processBytes(byte[] in, int inOff, int len, byte[] out, int outOff) throws DataLengthException {
        byte[] result = in;
        int off = inOff;
        int r = 0;
        for (StreamCipher streamCipher : ciphers) {
            r = streamCipher.processBytes(result, off, len, out, outOff);
            result = out;
            off = outOff;
        }
        return r;
    }

    @Override
    public void reset() {
        for (StreamCipher streamCipher : ciphers) {
            streamCipher.reset();
        }
    }

}
