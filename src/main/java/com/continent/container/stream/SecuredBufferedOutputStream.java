package com.continent.container.stream;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;

public class SecuredBufferedOutputStream extends BufferedOutputStream {

    public SecuredBufferedOutputStream(OutputStream out) {
        super(out);
    }

    public SecuredBufferedOutputStream(OutputStream out, int size) {
        super(out, size);
    }

    @Override
    public synchronized void flush() throws IOException {
        super.flush();
        Arrays.fill(buf, (byte) 0);
    }

}
