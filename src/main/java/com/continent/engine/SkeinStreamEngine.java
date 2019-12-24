package com.continent.engine;

import java.util.Arrays;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.SkeinParameters;
import org.bouncycastle.crypto.params.SkeinParameters.Builder;

import com.continent.random.SkeinRandom;

public class SkeinStreamEngine implements StreamCipher {

    private final int stateSize;
    private SkeinRandom random;
    private boolean init;
    private int index;
    private byte[] state;
    
    public SkeinStreamEngine(int stateSize) {
        super();
        this.stateSize = stateSize / 8;
    }

    @Override
    public void init(boolean forEncryption, CipherParameters params) throws IllegalArgumentException {
        if (params instanceof ParametersWithIV) {
            Builder paramsBuilder = new SkeinParameters.Builder();
            byte[] iv = ((ParametersWithIV)params).getIV();
            if (iv.length != stateSize) {
                throw new IllegalArgumentException();
            }
            paramsBuilder.setNonce(iv);
            CipherParameters keyParam = ((ParametersWithIV)params).getParameters();
            byte[] key = ((KeyParameter)keyParam).getKey();
            if (key.length != stateSize) {
                throw new IllegalArgumentException();
            }
            paramsBuilder.setKey(key);
            random = new SkeinRandom(null, paramsBuilder.build(), stateSize*8);
            
            for (int i = 0; i < 8; i++) {
                byte[] buf = new byte[stateSize];
                random.nextBytes(buf);
                Arrays.fill(buf, (byte)0);
            }
        }
    }

    @Override
    public String getAlgorithmName() {
        return "SkeinStream-" + (stateSize*8);
    }

    @Override
    public byte returnByte(byte in) {
        if (random == null) {
            throw new IllegalStateException(getAlgorithmName() + " not initialised");
        }

        if (!init || index == state.length) {
            init = true;
            index = 0;

            // generate random key length in range between 1 and 1024
            byte[] keyLength = new byte[2];
            random.nextBytes(keyLength);

            int length = keyLength[0] & 0xFF;
            length += (keyLength[1] & 0xFF) << 8;
            length = Math.abs(length) % 1023 + 1;
            Arrays.fill(keyLength, (byte)0);
            
            state = new byte[length];
            random.nextBytes(state);
        }
        byte res = (byte)((state[index] ^ in) & 0xFF);
        // burn it
        state[index] = 0;
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
