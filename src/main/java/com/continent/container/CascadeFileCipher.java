package com.continent.container;

import com.continent.engine.*;
import com.continent.engine.rc6.RC6_256_1024Engine;
import com.continent.engine.rc6.RC6_256_2048Engine;
import com.continent.engine.rc6.RC6_256_256Engine;
import com.continent.engine.rc6.RC6_256_512Engine;
import com.continent.random.RandomDelegator;
import com.continent.random.RandomService;
import com.continent.service.CombinationsGenerator;
import com.continent.service.CryptoService;
import com.continent.container.stream.NonClosableOutputStream;
import com.continent.container.stream.ProgressInputStream;
import net.sf.ntru.encrypt.EncryptionKeyPair;
import net.sf.ntru.encrypt.EncryptionPrivateKey;
import net.sf.ntru.encrypt.EncryptionPublicKey;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.crypto.digests.SkeinDigest;
import org.bouncycastle.crypto.engines.CAST6Engine;
import org.bouncycastle.crypto.engines.HC256Engine;
import org.bouncycastle.crypto.engines.SerpentEngine;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.atomic.AtomicLong;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

public class CascadeFileCipher {

    // 8 NTRU chunks by 106 bytes are enough to encrypt 768 bytes of key data
    private int ntruChunks = 8;

    private static byte[] HEADER = {0x18, 0x32, 0x71, 0x35};

    private static final int BUFFER_SIZE = 8192;

    private static final int saltSize = 64;
    private static final int ivSize = 128 + 128 + 128;
    private final int randomTailBytesLimit = 1024;

    public static final Map<String, Class<?>> CIPHERS = new HashMap<>();
    static  {
        CIPHERS.put("a", TwofishEngine.class);
        CIPHERS.put("b", SerpentEngine.class);
        CIPHERS.put("c", CAST6Engine.class);

        CIPHERS.put("d", RC6_256_256Engine.class);
        CIPHERS.put("e", RC6_256_512Engine.class);
        CIPHERS.put("f", RC6_256_1024Engine.class);
        CIPHERS.put("g", RC6_256_2048Engine.class);

        CIPHERS.put("h", Threefish256Engine.class);
        CIPHERS.put("i", Threefish512Engine.class);
        CIPHERS.put("j", Threefish1024Engine.class);

        CIPHERS.put("k", HC256Engine.class);

        CIPHERS.put("l", SkeinStream256Engine.class);
        CIPHERS.put("m", SkeinStream512Engine.class);
        CIPHERS.put("n", SkeinStream1024Engine.class);
    }

    private static final Object[] maxCiphers = new Object[] {
            new RC6_256_2048Engine(),
            new RC6_256_2048Engine(),
            new RC6_256_2048Engine(),
    };


    
    static final Map<Digest, Integer> digest2iterations = new LinkedHashMap<>();

    static {
        digest2iterations.put(new RIPEMD160Digest(), 655331);
        digest2iterations.put(new SkeinDigest(SkeinDigest.SKEIN_256, 256), 250000);
        digest2iterations.put(new SkeinDigest(SkeinDigest.SKEIN_512, 512), 250000);
        digest2iterations.put(new SkeinDigest(SkeinDigest.SKEIN_1024, 1024), 250000);
    }

    private String outputDir;

    public CascadeFileCipher() {
    }

    private void burn(byte[] buffer) {
        Arrays.fill(buffer, (byte)0);
    }

    public void encrypt(OutputStream outputStream, List<Path> inputFiles, byte[] publicKey, List<Object> ciphers) throws IOException {
        RandomService randomService = new RandomService();
        RandomDelegator generator = randomService.getNonceGenerator();

        byte[] keyData = new byte[CryptoService.ntruDecryptedChunkSize*ntruChunks];
        RandomDelegator keyGenerator = randomService.getKeyGenerator();
        keyGenerator.nextBytes(keyData);

        byte[] encryptedKeyData = CryptoService.encryptCipherKeys(keyData, new EncryptionPublicKey(publicKey), randomService);
        outputStream.write(encryptedKeyData);

        encrypt(outputStream, inputFiles, ciphers, generator, keyData);
        burn(keyData);
        randomService.shutdown();
    }

    public void encrypt(OutputStream outputStream, List<Path> inputFiles, byte[] password, List<Object> ciphers, Digest digest, int iterations) throws IOException {
        RandomService randomService = new RandomService();
        RandomDelegator generator = randomService.getNonceGenerator();

        byte[] salt = new byte[CascadeFileCipher.saltSize];
        generator.nextBytes(salt);
        outputStream.write(salt);

        KeyGenerator kg = new KeyGenerator(password, salt, ciphers, digest, iterations);
        byte[] keyData = kg.generateKeyData();

        encrypt(outputStream, inputFiles, ciphers, generator, keyData);
        burn(keyData);
        randomService.shutdown();
    }

    private void encrypt(OutputStream outputStream, List<Path> inputFiles, List<Object> ciphers, RandomDelegator generator, byte[] keyData) throws IOException {
        byte[] iv = new byte[CascadeFileCipher.ivSize];
        generator.nextBytes(iv);
        outputStream.write(iv);

        CryptoService service = new CryptoService();
        service.setEncoderCiphers(ciphers, keyData, iv);

        OutputStream fos = service.getEncryptedOutputStream(outputStream);
        fos.write(HEADER);

        final ZipOutputStream zipOut = new ZipOutputStream(new NonClosableOutputStream(fos));
        zipOut.setLevel(ZipOutputStream.STORED);

        final AtomicLong size = new AtomicLong();
        for (Path inputFile : inputFiles) {
            if (Files.isDirectory(inputFile)) {
                Files.walkFileTree(inputFile, new SimpleFileVisitor<Path>() {
                    @Override
                    public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                        size.addAndGet(Files.size(file));
                        return FileVisitResult.CONTINUE;
                    }
                });
            } else {
                size.addAndGet(Files.size(inputFile));
            }
        }

        final ProgressInputStream pis = new ProgressInputStream(size.get(), true, ciphers);
        for (final Path inputFile : inputFiles) {
            if (Files.isDirectory(inputFile)) {
                Files.walkFileTree(inputFile, new SimpleFileVisitor<Path>() {
                    public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                        zipOut.putNextEntry(new ZipEntry(inputFile.relativize(file).toString()));
                        InputStream is = Files.newInputStream(file);
                        pis.updateInput(is);
                        copy(pis, zipOut);
                        zipOut.closeEntry();
                        return FileVisitResult.CONTINUE;
                    }
                });
            } else {
                ZipEntry zipEntry = new ZipEntry(inputFile.getFileName().toString());
                zipOut.putNextEntry(zipEntry);

                InputStream is = Files.newInputStream(inputFile);
                pis.updateInput(is);
                copy(pis, zipOut);
                zipOut.closeEntry();
            }
        }
        zipOut.close();

        byte[] bytes = new byte[generator.nextInt(randomTailBytesLimit)];
        generator.nextBytes(bytes);
        outputStream.write(bytes);
        outputStream.close();

        System.out.println("\rEncryption has been completed!                                                             ");
    }

    private static long copy(InputStream source, OutputStream sink)
            throws IOException
    {
        long nread = 0L;
        byte[] buf = new byte[BUFFER_SIZE];
        int n;
        while ((n = source.read(buf)) > 0) {
            sink.write(buf, 0, n);
            nread += n;
        }
        return nread;
    }

    public void decrypt(String outputDir, byte[] password, Path filePath, Digest digest, int iterations) throws IOException {
        this.outputDir = outputDir;
        
        Map<Digest, Integer> digest2iterations = Collections.singletonMap(digest, iterations);
        decrypt(password, filePath, digest2iterations);
    }

    public void decrypt(String outputDir, byte[] password, Path filePath) throws IOException {
        this.outputDir = outputDir;
        decrypt(password, filePath, digest2iterations);
    }

    public void decrypt(String outputDir, byte[] publicKey, byte[] privateKey, Path filePath) throws IOException {
        this.outputDir = outputDir;
        decrypt(publicKey, privateKey, filePath);
    }

    private void decrypt(byte[] publicKey, byte[] privateKey, Path filePath) throws IOException {
        InputStream inputStream = Files.newInputStream(filePath, StandardOpenOption.READ);

        long fileSize = Files.size(filePath);
        if (fileSize < ivSize + 16) {
            throw new IllegalStateException();
        }

        byte[] encryptedKeys = new byte[CryptoService.ntruEncryptedChunkSize*ntruChunks];
        inputStream.read(encryptedKeys);

        byte[] iv = new byte[ivSize];
        inputStream.read(iv);

        byte[] encryptedHeader = new byte[HEADER.length];
        inputStream.read(encryptedHeader);

        byte[] keyData = CryptoService.decryptCipherKeys(ByteBuffer.wrap(encryptedKeys),
                new EncryptionKeyPair(new EncryptionPrivateKey(privateKey), new EncryptionPublicKey(publicKey)), ntruChunks);

        CombinationsGenerator combinationsGenerator = new CombinationsGenerator();
        List<List<Object>> combinations = combinationsGenerator.generate(true);
        for (List<Object> combination : combinations) {
            CryptoService service = new CryptoService();
            service.setDecoderCiphers(combination, iv, keyData);

            InputStream decryptedHeaderStream = service.getDecryptedInputStream(new ByteArrayInputStream(encryptedHeader));
            byte[] decryptedHeader = new byte[HEADER.length];
            decryptedHeaderStream.read(decryptedHeader);
            if (Arrays.equals(decryptedHeader, HEADER)) {
                burn(keyData);

                ZipInputStream zis = new ZipInputStream(service.getDecryptedInputStream(inputStream));
                ZipEntry zipEntry = zis.getNextEntry();
                ProgressInputStream pis = new ProgressInputStream(fileSize, false, combination);

                while (zipEntry != null) {
                    File newFile = newFile(new File(outputDir), zipEntry);
                    FileOutputStream fos3 = new FileOutputStream(newFile);

                    pis.updateInput(zis);
                    copy(pis, fos3);
                    fos3.close();
                    zipEntry = zis.getNextEntry();
                }
                zis.closeEntry();
                zis.close();

                System.out.println("\rDecryption has been completed!                                             ");
                return;
            }
        }

        System.out.println("Unable to decrypt container!");
    }

    private void decrypt(byte[] password, Path filePath, Map<Digest, Integer> digest2iterations) throws IOException {
        InputStream inputStream = Files.newInputStream(filePath, StandardOpenOption.READ);

        long fileSize = Files.size(filePath);
        if (fileSize < saltSize + ivSize + 16) {
              throw new IllegalStateException();
        }

        byte[] salt = new byte[saltSize];
        inputStream.read(salt);

        byte[] iv = new byte[ivSize];
        inputStream.read(iv);

        CombinationsGenerator combinationsGenerator = new CombinationsGenerator();

        List<List<Object>> combinations = combinationsGenerator.generate(true);

        byte[] encryptedHeader = new byte[HEADER.length];
        inputStream.read(encryptedHeader);

        for (Entry<Digest, Integer> entry : digest2iterations.entrySet()) {
            KeyGenerator kg = new KeyGenerator(password, salt, Arrays.asList(maxCiphers), entry.getKey(), entry.getValue());
            byte[] keyData = kg.generateKeyData();

            for (List<Object> combination : combinations) {
                CryptoService service = new CryptoService();
                service.setDecoderCiphers(combination, iv, keyData);

                InputStream decryptedHeaderStream = service.getDecryptedInputStream(new ByteArrayInputStream(encryptedHeader));
                byte[] decryptedHeader = new byte[HEADER.length];
                decryptedHeaderStream.read(decryptedHeader);
                if (Arrays.equals(decryptedHeader, HEADER)) {
                    burn(keyData);

                    ZipInputStream zis = new ZipInputStream(service.getDecryptedInputStream(inputStream));
                    ZipEntry zipEntry = zis.getNextEntry();
                    ProgressInputStream pis = new ProgressInputStream(fileSize, false, combination);

                    while (zipEntry != null) {
                        File newFile = newFile(new File(outputDir), zipEntry);
                        FileOutputStream fos3 = new FileOutputStream(newFile);

                        pis.updateInput(zis);
                        copy(pis, fos3);
                        fos3.close();
                        zipEntry = zis.getNextEntry();
                    }
                    zis.closeEntry();
                    zis.close();

                    System.out.println("\rDecryption has been completed!                                               ");
                    return;
                }
            }
        }

        System.out.println("Unable to decrypt container!");
    }

    private static File newFile(File destinationDir, ZipEntry zipEntry) throws IOException {
        File destFile = new File(destinationDir, zipEntry.getName());

        destFile.getParentFile().mkdirs();
        String destDirPath = destinationDir.getCanonicalPath();
        String destFilePath = destFile.getCanonicalPath();

        if (!destFilePath.startsWith(destDirPath + File.separator)) {
            throw new IOException("Entry is outside of the target dir: " + zipEntry.getName());
        }

        return destFile;
    }

}
