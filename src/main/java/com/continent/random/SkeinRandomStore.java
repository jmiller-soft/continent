package com.continent.random;

import java.io.*;

public class SkeinRandomStore extends SkeinRandom {

    private final OutputStream os;

    public SkeinRandomStore(OutputStream os, int rounds) {
        super(null, rounds);
        this.os = os;
    }

    @Override
    public synchronized void nextBytes(byte[] bytes, int start, int len) {
        super.nextBytes(bytes, start, len);
        try {
            os.write(bytes, start, len);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
