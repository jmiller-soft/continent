package com.continent.container;

import com.continent.container.stream.ProgressInputStream;
import com.continent.container.stream.SplittedInputStream;
import com.continent.engine.XorFileEngine;
import com.continent.random.SkeinRandomCompressedInputStream;
import com.continent.service.CombinationsGenerator;
import com.continent.service.CryptoService;
import net.sf.ntru.encrypt.EncryptionKeyPair;
import net.sf.ntru.encrypt.EncryptionPrivateKey;
import net.sf.ntru.encrypt.EncryptionPublicKey;
import org.bouncycastle.crypto.io.CipherInputStream;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class ContainerDecryptor extends ContainerSupport {

    public static class OTPContainerDecryptor extends ContainerDecryptor {

        private Path otpFilePath;
        private boolean compressed;

        public void setOtpFilePath(Path otpFilePath) {
            this.otpFilePath = otpFilePath;
        }

        public void setCompressed(boolean compressed) {
            this.compressed = compressed;
        }

        public void decrypt() throws IOException {
            initInputStream();

            InputStream otpInputStream;
            if (Files.exists(SplittedInputStream.getPartPath(otpFilePath, 1))) {
                otpInputStream = new SplittedInputStream(otpFilePath);
            } else {
                otpInputStream = Files.newInputStream(otpFilePath, StandardOpenOption.READ);
            }
            otpInputStream = new BufferedInputStream(otpInputStream, 1024 * 1024);
            if (compressed) {
                otpInputStream = new SkeinRandomCompressedInputStream(otpInputStream);
            }

            InputStream inputStream = new CipherInputStream(encryptedInputStream, new XorFileEngine(otpInputStream));
            decrypt(inputStream, "One-time pad");
        }


    }

    public static class PasswordContainerDecryptor extends ContainerDecryptor {

        private byte[] password;
        private int iterations;
        private KeyGenerator keyGenerator;

        public void setKeyGenerator(KeyGenerator keyGenerator) {
            this.keyGenerator = keyGenerator;
        }

        public void setPassword(byte[] password) {
            this.password = password;
        }

        public void setIterations(int iterations) {
            this.iterations = iterations;
        }

        public void decrypt() throws IOException {
            initInputStream();

            if (fileSize < saltSize + ivSize + 16) {
                  throw new IllegalStateException();
            }

            byte[] salt = new byte[saltSize];
            encryptedInputStream.read(salt);

            byte[] iv = new byte[ivSize];
            encryptedInputStream.read(iv);

            byte[] encryptedHeader = new byte[HEADER.length];
            encryptedInputStream.read(encryptedHeader);

            byte[] keyData = keyGenerator.generateKeyData(password, salt, maxKeySize, iterations);

            decrypt(iv, encryptedHeader, keyData);
        }

    }

    public static class NTRUContainerDecryptor extends ContainerDecryptor {

        private byte[] publicKey;
        private byte[] privateKey;

        public void setPublicKey(byte[] publicKey) {
            this.publicKey = publicKey;
        }

        public void setPrivateKey(byte[] privateKey) {
            this.privateKey = privateKey;
        }

        public void decrypt() throws IOException {
            initInputStream();

            if (fileSize < ivSize + 16) {
                throw new IllegalStateException();
            }

            byte[] encryptedKeys = new byte[CryptoService.ntruEncryptedChunkSize*ntruChunks];
            encryptedInputStream.read(encryptedKeys);

            byte[] iv = new byte[ivSize];
            encryptedInputStream.read(iv);

            byte[] encryptedHeader = new byte[HEADER.length];
            encryptedInputStream.read(encryptedHeader);

            byte[] keyData = CryptoService.decryptCipherKeys(new ByteArrayInputStream(encryptedKeys),
                    new EncryptionKeyPair(new EncryptionPrivateKey(privateKey), new EncryptionPublicKey(publicKey)));

            decrypt(iv, encryptedHeader, keyData);
        }

    }

    private String outputDir;
    private Path encryptedFilePath;
    InputStream encryptedInputStream;
    long fileSize;

    public void setOutputDir(String outputDir) {
        this.outputDir = outputDir;
    }

    public void setEncryptedFilePath(Path encryptedFilePath) {
        this.encryptedFilePath = encryptedFilePath;
    }

    void initInputStream() throws IOException {
        if (Files.exists(SplittedInputStream.getPartPath(encryptedFilePath, 1))) {
            encryptedInputStream = new SplittedInputStream(encryptedFilePath);

            for (int part = 1; part < 100000; part++) {
                Path partPath = Paths.get(encryptedFilePath.toAbsolutePath().toString() + String.format(".%3s", part).replace(' ', '0'));
                if (!Files.exists(partPath)) {
                    break;
                }
                fileSize += Files.size(partPath);
            }
        } else {
            encryptedInputStream = Files.newInputStream(encryptedFilePath, StandardOpenOption.READ);
            fileSize = Files.size(encryptedFilePath);

        }
        encryptedInputStream = new BufferedInputStream(encryptedInputStream, 1024*1024);
    }

    void decrypt(byte[] iv, byte[] encryptedHeader, byte[] keyData) throws IOException {
        CombinationsGenerator combinationsGenerator = new CombinationsGenerator();
        List<List<Object>> combinations = combinationsGenerator.generate(true);
        for (List<Object> combination : combinations) {
            if (decrypt(encryptedInputStream, iv, encryptedHeader, keyData, combination)) {
                return;
            }
        }

        burn(keyData);
        System.out.println("Unable to decrypt container!");
    }

    boolean decrypt(InputStream inputStream, byte[] iv, byte[] encryptedHeader, byte[] keyData, List<Object> combination) throws IOException {
        CryptoService service = new CryptoService();
        service.setDecoderCiphers(combination, iv, keyData);
        String cipherName = getCipherName(combination);

        InputStream decryptedHeaderStream = service.getDecryptedInputStream(new ByteArrayInputStream(encryptedHeader));
        byte[] decryptedHeader = new byte[HEADER.length];
        decryptedHeaderStream.read(decryptedHeader);

        if (!Arrays.equals(decryptedHeader, HEADER)) {
            return false;
        }

        burn(keyData);

        inputStream = service.getDecryptedInputStream(inputStream);

        if (!decrypt(inputStream, cipherName)) {
            return false;
        }
        return true;
    }

    boolean decrypt(InputStream inputStream, String cipherName) throws IOException {
        ZipInputStream zis = new ZipInputStream(inputStream);
        ZipEntry zipEntry = zis.getNextEntry();
        ProgressInputStream pis = new ProgressInputStream(fileSize, false, cipherName);

        if (zipEntry == null) {
            System.out.println("Unable to decrypt container!");
            zis.close();
            return false;
        }

        while (zipEntry != null) {
            if (zipEntry.isDirectory()) {
                String name = zipEntry.getName().replace("/", "");
                Path p = Paths.get(outputDir).resolve(name);
                Files.createDirectories(p);
            } else {
                String name = zipEntry.getName().replace("/", "");
                Path p = Paths.get(outputDir).resolve(name);
                OutputStream fos3 = Files.newOutputStream(p);
                fos3 = new BufferedOutputStream(fos3, 1024*1024);

                pis.updateInput(zis);
                copy(pis, fos3);
                fos3.close();
                p.toFile().setLastModified(zipEntry.getTime());
            }

            zis.closeEntry();
            zipEntry = zis.getNextEntry();
        }
        zis.close();

        System.out.println("\rDecryption has been completed!                                               ");
        return true;
    }

}
