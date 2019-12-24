package com.continent.container.stream;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.StreamCipher;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;

public class ProgressInputStream extends FilterInputStream {

    private final long totalSize;
    private long readSize;
    private final boolean encryption;
    private final List<Object> ciphers;

    public ProgressInputStream(long totalSize, boolean encryption, List<Object> ciphers) {
        super(null);
        this.totalSize = totalSize;
        this.encryption = encryption;
        this.ciphers = ciphers;
    }

    public void updateInput(InputStream in) {
        this.in = in;
    }
    
    @Override
    public int read() throws IOException {
        throw new UnsupportedOperationException();
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        int result = super.read(b, off, len);
        readSize += result;
        int progress = (int) (((double)readSize * 100) / totalSize);

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

        if (encryption) {
            System.out.print("\rEncrypting (" + s + ") - " + progress + "%");
        } else {
            System.out.print("\rDecrypting (" + s + ") - " + progress + "%");
        }
        return result;
    }
}
