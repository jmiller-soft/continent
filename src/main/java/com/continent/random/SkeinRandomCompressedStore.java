package com.continent.random;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public class SkeinRandomCompressedStore extends SkeinRandom {

    private int counter;
    private DataOutputStream dos;
    private OutputStream os;
    private int blockSize;
    private int rounds;

    public SkeinRandomCompressedStore(OutputStream os, int blockSize, int rounds) {
        super(null, rounds);
        this.os = os;
        this.blockSize = blockSize;
        this.rounds = rounds;
    }

    @Override
    public synchronized void addSeedMaterial(byte[] seed) {
        super.addSeedMaterial(seed);
        try {
            if (dos == null) {
                dos = new DataOutputStream(os);
                try {
                    dos.writeShort(rounds);
                    dos.writeShort(blockSize);
                    dos.writeShort(seed.length);
                    dos.write(seed);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            } else {
                dos.writeShort(((Integer) counter).shortValue());
                dos.write(seed);
            }
            counter = 0;
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public synchronized void nextBytes(byte[] bytes, int start, int len) {
        super.nextBytes(bytes, start, len);
        counter++;
    }

    public void close() {
        if (counter == 0) {
            return;
        }

        try {
            dos.writeShort(((Integer) counter).shortValue());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
