package com.continent.container.stream;

import org.bouncycastle.crypto.io.CipherOutputStream;

import java.io.*;

public class DecryptedInputStream extends FilterInputStream {

    private final CipherOutputStream cos;
    private final ByteArrayOutputStream os;

    public DecryptedInputStream(InputStream in, CipherOutputStream cos, ByteArrayOutputStream os) {
        super(in);

        this.in = in;
        this.cos = cos;
        this.os = os;
    }

    @Override
    public int read() throws IOException {
        cos.write(in.read());
        byte[] bb = os.toByteArray();
        os.reset();
        return new ByteArrayInputStream(bb).read();
    }

    @Override
    public int read(byte[] b) throws IOException {
        return read(b, 0, b.length);
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        byte[] bb = new byte[b.length];
        int size = in.read(bb, off, len);
        cos.write(bb, 0, size);
        byte[] decryptedBytes = os.toByteArray();
        os.reset();
        System.arraycopy(decryptedBytes, 0, b, 0, decryptedBytes.length);
        return decryptedBytes.length;
    }
}
