package com.continent.random.entropy;

import io.netty.util.internal.PlatformDependent;

import java.io.File;
import java.io.InputStream;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;

public class NativeJitterEntropy implements EntropySource {

    private final ExecutorService executorService = Executors.newSingleThreadExecutor();

    static {
        if (PlatformDependent.isAndroid()) {
            System.loadLibrary("native-lib");
        } else {
            String libName = "native-lib.so"; // The name of the file in resources/ dir
            if (PlatformDependent.isWindows()) {
                libName = "native-lib.dll";
            }
            URL url = NativeJitterEntropy.class.getResource("/" + libName);
            try {
                File tmpDir = Files.createTempDirectory("native-lib").toFile();
                tmpDir.deleteOnExit();
                File nativeLibTmpFile = new File(tmpDir, libName);
                nativeLibTmpFile.deleteOnExit();
                try (InputStream in = url.openStream()) {
                    Files.copy(in, nativeLibTmpFile.toPath());
                }
                System.load(nativeLibTmpFile.getAbsolutePath());
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
    }

    private native int initRandom();

    private native void generateRandom(BlockingQueue<Integer> request, BlockingQueue<byte[]> response);

    final BlockingQueue<byte[]> randomData = new LinkedBlockingQueue<byte[]>();
    final BlockingQueue<Integer> randomRequest = new LinkedBlockingQueue<Integer>();
    private volatile boolean started = false;

    public NativeJitterEntropy() {
        int status = initRandom();
        if (status != 0) {
            throw new IllegalStateException("Unable to init Random generator. Status: " + status);
        }
    }

    public void fill(ByteBuffer byteBuffer) {
        if (!started) {
            started = true;
            executorService.execute(new Runnable() {
                @Override
                public void run() {
                    generateRandom(randomRequest, randomData);
                }
            });
        }

        generate(randomData, byteBuffer, randomRequest);
    }

    private void generate(BlockingQueue<byte[]> randomData, ByteBuffer byteBuffer, BlockingQueue<Integer> randomSize) {
        try {
            randomSize.add(byteBuffer.limit());
            byte[] bytes = randomData.take();
//            System.out.println(System.identityHashCode(randomData) + " " + ByteBufUtil.hexDump(bytes));
            byteBuffer.put(bytes);
            Arrays.fill(bytes, (byte)0);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void shutdown() {
        randomRequest.add(-1);
        executorService.shutdown();
    }
}
