package com.continent.container.stream;

import java.io.FilterOutputStream;
import java.io.OutputStream;

public class NonClosableOutputStream extends FilterOutputStream {

    public NonClosableOutputStream(OutputStream out) {
        super(out);
    }

    @Override
    public void close() {

    }

}
