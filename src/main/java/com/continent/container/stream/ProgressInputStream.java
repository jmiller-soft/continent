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
    private final String cipher;

    public ProgressInputStream(long totalSize, boolean encryption, String cipher) {
        super(null);
        this.totalSize = totalSize;
        this.encryption = encryption;
        this.cipher = cipher;
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

        if (encryption) {
            System.out.print("\rEncrypting (" + cipher + ") - " + progress + "%");
        } else {
            System.out.print("\rDecrypting (" + cipher + ") - " + progress + "%");
        }
        return result;
    }
}
