package com.continent.container.stream;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

public class SplittedOutputStream extends OutputStream {

    private long currentPartSize;
    private Path partPath;
    private long part = 1;

    private final long partSize;
    private final Path path;

    private OutputStream outputStream;

    public SplittedOutputStream(Path path, long partSize) {
        this.path = path;
        this.partSize = partSize;
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        if (outputStream == null) {
            partPath = Paths.get(path.toAbsolutePath().toString()  + String.format(".%3s", part).replace(' ', '0'));
            outputStream = Files.newOutputStream(partPath, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        }

        long remainLen = partSize - currentPartSize;
        if (remainLen >= len) {
            outputStream.write(b, off, len);
            currentPartSize += len;
        } else if (remainLen > 0) {
            outputStream.write(b, off, (int) remainLen);
            currentPartSize += remainLen;
        }

        if (currentPartSize == partSize) {
            currentPartSize = 0;
            part++;
            outputStream.close();
            outputStream = null;
        }
        if (remainLen < len) {
            write(b, (int)(off+remainLen), (int)(len-remainLen));
        }
    }

    @Override
    public void write(int b) throws IOException {
        if (outputStream == null) {
            partPath = Paths.get(path.toAbsolutePath().toString()  + String.format(".%3s", part).replace(' ', '0'));
            outputStream = Files.newOutputStream(partPath, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        }

        outputStream.write(b);
        currentPartSize++;

        if (currentPartSize == partSize) {
            currentPartSize = 0;
            part++;
            outputStream.close();
            outputStream = null;
        }
    }

    @Override
    public void flush() throws IOException {
        outputStream.flush();
    }

    @Override
    public void close() throws IOException {
        if (outputStream == null) {
            return;
        }
        outputStream.close();
    }
}
