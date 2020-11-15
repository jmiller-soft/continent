package com.continent.container;

import com.continent.container.stream.NonClosableOutputStream;
import com.continent.container.stream.ProgressInputStream;
import com.continent.container.stream.SecuredBufferedOutputStream;
import com.continent.container.stream.SplittedOutputStream;
import com.continent.random.*;
import com.continent.service.CryptoService;
import com.google.common.base.Stopwatch;
import net.sf.ntru.encrypt.EncryptionPublicKey;
import org.bouncycastle.crypto.io.CipherOutputStream;

import java.io.*;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class ContainerEncryptor extends ContainerSupport {

    public static class OTPContainerEncryptor extends ContainerEncryptor {

        private int roundsMultiplier;
        private boolean compressed;
        private Path otpFilePath;

        public void setRoundsMultiplier(int roundsMultiplier) {
            this.roundsMultiplier = roundsMultiplier;
        }

        public void setCompressed(boolean compressed) {
            this.compressed = compressed;
        }

        public void setOtpFilePath(Path otpFilePath) {
            this.otpFilePath = otpFilePath;
        }

        public void encrypt() throws IOException {
            OutputStream outputStream = getOutputStream();

            OutputStream otpOutputStream = Files.newOutputStream(otpFilePath, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);

            SkeinRandom random;
            if (compressed) {
                otpOutputStream = new SecuredBufferedOutputStream(otpOutputStream);
                random = new SkeinRandomCompressedStore(otpOutputStream, 512, 72 * roundsMultiplier);
            } else {
                otpOutputStream = new SecuredBufferedOutputStream(otpOutputStream, 1024*1024);
                random = new SkeinRandomStore(otpOutputStream, 72 * roundsMultiplier);
            }
            OneTimePadGenerator oneTimePadGenerator = new OneTimePadGenerator(random);
            OutputStream fos = new CipherOutputStream(outputStream, new OneTimePadEngine(oneTimePadGenerator, 512));

            try {
                encrypt("One-time pad", fos);
            } finally {
                outputStream.close();
                oneTimePadGenerator.shutdown();
                if (random instanceof SkeinRandomCompressedStore) {
                    ((SkeinRandomCompressedStore) random).close();
                }
                otpOutputStream.close();
            }
        }

    }

    public static class PasswordContainerEncryptor extends ContainerEncryptor {

        private byte[] password;
        private List<Object> ciphers;
        private int iterations;
        private KeyGenerator keyGenerator;

        public void setKeyGenerator(KeyGenerator keyGenerator) {
            this.keyGenerator = keyGenerator;
        }

        public void setPassword(byte[] password) {
            this.password = password;
        }

        public void setCiphers(List<Object> ciphers) {
            this.ciphers = ciphers;
        }

        public void setIterations(int iterations) {
            this.iterations = iterations;
        }

        public void encrypt() throws IOException {
            OutputStream outputStream = getOutputStream();

            RandomService randomService = new RandomService(0, 0);
            RandomDelegator generator = randomService.getNonceGenerator();

            byte[] salt = new byte[saltSize];
            generator.nextBytes(salt);
            outputStream.write(salt);

            byte[] keyData = keyGenerator.generateKeyData(password, salt, maxKeySize, iterations);

            try {
                encrypt(outputStream, ciphers, generator, keyData);
            } finally {
                burn(keyData);
                randomService.shutdown();
            }
        }

    }

    public static class NTRUContainerEncryptor extends ContainerEncryptor {

        private byte[] publicKey;
        private List<Object> ciphers;

        public void setPublicKey(byte[] publicKey) {
            this.publicKey = publicKey;
        }

        public void setCiphers(List<Object> ciphers) {
            this.ciphers = ciphers;
        }

        public void encrypt() throws IOException {
            OutputStream outputStream = getOutputStream();

            RandomService randomService = new RandomService(0, 0);
            RandomDelegator generator = randomService.getNonceGenerator();

            byte[] keyData = new byte[CryptoService.ntruDecryptedChunkSize*ntruChunks];
            RandomDelegator keyGenerator = randomService.getKeyGenerator();
            keyGenerator.nextBytes(keyData);

            byte[] encryptedKeyData = CryptoService.encryptCipherKeys(keyData, new EncryptionPublicKey(publicKey), randomService.getKeyGenerator());
            outputStream.write(encryptedKeyData);

            try {
                encrypt(outputStream, ciphers, generator, keyData);
            } finally {
                burn(keyData);
                randomService.shutdown();
            }
        }
    }

    private Path encryptedFilePath;
    private List<Path> inputFiles;
    private Long volumeSize;

    public void setEncryptedFilePath(Path encryptedFilePath) {
        this.encryptedFilePath = encryptedFilePath;
    }

    public void setInputFiles(List<Path> inputFiles) {
        this.inputFiles = inputFiles;
    }

    public void setVolumeSize(Long volumeSize) {
        this.volumeSize = volumeSize;
    }

    OutputStream getOutputStream() throws IOException {
        OutputStream outputStream;
        if (volumeSize == null) {
            outputStream = Files.newOutputStream(encryptedFilePath, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        } else {
            outputStream = new SplittedOutputStream(encryptedFilePath, volumeSize);
        }
        outputStream = new BufferedOutputStream(outputStream, 1024*1024);
        return outputStream;
    }

    void encrypt(OutputStream outputStream, List<Object> ciphers, RandomDelegator generator, byte[] keyData) throws IOException {
        Stopwatch s = Stopwatch.createStarted();

        byte[] iv = new byte[ivSize];
        generator.nextBytes(iv);
        outputStream.write(iv);

        CryptoService service = new CryptoService();
        service.setEncoderCiphers(ciphers, keyData, iv);
        String cipherName = getCipherName(ciphers);

        OutputStream fos = service.getEncryptedOutputStream(outputStream);
        fos.write(HEADER);

        encrypt(cipherName, fos);

        byte[] bytes = new byte[generator.nextInt(randomTailBytesLimit)];
        generator.nextBytes(bytes);
        outputStream.write(bytes);

        outputStream.close();
        System.out.printf("\rEncryption has been completed! %s                                                            ", s);
    }

    void encrypt(String cipherName, OutputStream fos) throws IOException {
        Stopwatch s = Stopwatch.createStarted();

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

        final ProgressInputStream pis = new ProgressInputStream(size.get(), true, cipherName);
        for (final Path inputFile : inputFiles) {
            if (Files.isDirectory(inputFile)) {
                Files.walkFileTree(inputFile, new SimpleFileVisitor<Path>() {

                    @Override
                    public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) throws IOException {
                        ZipEntry e = new ZipEntry(inputFile.getParent().relativize(dir).toString() + "/");
                        zipOut.putNextEntry(e);
                        zipOut.closeEntry();
                        return super.preVisitDirectory(dir, attrs);
                    }

                    @Override
                    public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                        ZipEntry e = new ZipEntry(inputFile.getParent().relativize(file).toString());
                        e.setTime(attrs.lastModifiedTime().toMillis());
                        zipOut.putNextEntry(e);

                        InputStream is = Files.newInputStream(file);
                        is = new BufferedInputStream(is, 1024*1024);
                        pis.updateInput(is);
                        copy(pis, zipOut);
                        zipOut.closeEntry();
                        is.close();
                        return FileVisitResult.CONTINUE;
                    }
                });
            } else {
                ZipEntry zipEntry = new ZipEntry(inputFile.getFileName().toString());
                zipOut.putNextEntry(zipEntry);

                InputStream is = Files.newInputStream(inputFile);
                is = new BufferedInputStream(is, 1024*1024);
                pis.updateInput(is);
                copy(pis, zipOut);
                zipOut.closeEntry();
                is.close();
            }
        }
        zipOut.flush();
        zipOut.close();

        System.out.printf("\rEncryption has been completed! %s                                                            ", s);
    }

}
