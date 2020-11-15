package com.continent.random;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;

public class SkeinRandomCompressedInputStream extends InputStream {

    private int bufIndex;
    private DataInputStream dis;
    private SkeinRandom random;
    private int counter;
    private byte[] buf;

    public SkeinRandomCompressedInputStream(InputStream is) {
        this.dis = new DataInputStream(is);
        try {
            short rounds = dis.readShort();
            short bufferSize = dis.readShort();
            short seedSize = dis.readShort();
            byte[] seed = new byte[seedSize];
            dis.read(seed);
            random = new SkeinRandom(seed, rounds);
            counter = dis.readShort();
            buf = new byte[bufferSize];
            bufIndex = buf.length;

            readNextSeed();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void readNextSeed() throws IOException {
        while (counter == 0) {
            byte[] addedSeed = new byte[8];
            dis.read(addedSeed);
            random.addSeedMaterial(addedSeed);
            counter = dis.readShort();
        }
    }

    @Override
    public int read() throws IOException {
        if (bufIndex == buf.length) {
            random.nextBytes(buf);
            bufIndex = 0;
            counter--;
            readNextSeed();
        }

        return buf[bufIndex++] & 0xFF;
    }
}
