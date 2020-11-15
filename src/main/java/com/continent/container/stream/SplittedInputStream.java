package com.continent.container.stream;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

public class SplittedInputStream extends InputStream {

    private long currentPartSize;
    private long partSize;
    private Path partPath;
    private int part = 1;

    private final Path path;

    private InputStream inputStream;

    public SplittedInputStream(Path path) {
        this.path = path;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        updateInputStream();

        boolean close = false;
        int readBytes = 0;
        long remainLen = partSize - currentPartSize;
        if (remainLen >= len) {
            readBytes += inputStream.read(b, off, len);
            currentPartSize += len;
            if (readBytes < len) {
                close = true;
            }
        } else if (remainLen > 0) {
            readBytes += inputStream.read(b, off, (int) remainLen);
            currentPartSize += remainLen;
            if (readBytes < remainLen) {
                close = true;
            }
        }

        if (currentPartSize == partSize || close) {
            currentPartSize = 0;
            part++;
            inputStream.close();
            inputStream = null;
        } else if (remainLen < len) {
            readBytes += read(b, (int)(off+remainLen), (int)(len-remainLen));
        }
        return readBytes;
    }

    @Override
    public int read() throws IOException {
        updateInputStream();

        int b = inputStream.read();
        currentPartSize++;

        if (currentPartSize == partSize) {
            currentPartSize = 0;
            part++;
            inputStream.close();
            inputStream = null;
        }
        return b;
    }

    private void updateInputStream() throws IOException {
        if (inputStream == null) {
            partPath = getPartPath(path, part);
            partSize = Files.size(partPath);
            inputStream = Files.newInputStream(partPath, StandardOpenOption.READ);
        }
    }

    public static Path getPartPath(Path path, int part) {
        return Paths.get(path.toAbsolutePath().toString() + String.format(".%3s", part).replace(' ', '0'));
    }

    @Override
    public void close() throws IOException {
        if (inputStream == null) {
            return;
        }
        inputStream.close();
    }
}
