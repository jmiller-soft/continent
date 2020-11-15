package com.continent.service;

import com.continent.engine.*;
import com.continent.engine.rc6.RC6_256_1024Engine;
import com.continent.engine.rc6.RC6_256_2048Engine;
import com.continent.engine.rc6.RC6_256_256Engine;
import com.continent.engine.rc6.RC6_256_512Engine;
import net.sf.ntru.encrypt.EncryptionKeyPair;
import net.sf.ntru.encrypt.EncryptionParameters;
import net.sf.ntru.encrypt.EncryptionPublicKey;
import net.sf.ntru.encrypt.NtruEncrypt;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.CAST6Engine;
import org.bouncycastle.crypto.engines.HC256Engine;
import org.bouncycastle.crypto.engines.SerpentEngine;
import org.bouncycastle.crypto.io.CipherOutputStream;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.io.*;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.*;

public class CryptoService {

    class DecryptedInputStream extends FilterInputStream {

        private final CipherOutputStream cos;
        private final ByteArrayOutputStream os;

        public DecryptedInputStream(InputStream in, StreamCipher decryptCipher) {
            super(in);

            this.in = in;
            this.os = new ByteArrayOutputStream();
            this.cos = new CipherOutputStream(os, decryptCipher);
        }

        @Override
        public int read() throws IOException {
            cos.write(in.read());
            byte[] bb = os.toByteArray();
            os.reset();
            return new ByteArrayInputStream(bb).read();
        }

        @Override
        public int read(byte[] b) throws IOException {
            return read(b, 0, b.length);
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            int size = in.read(b, off, len);
            cos.write(b, off, size);
            byte[] decryptedBytes = os.toByteArray();
            os.reset();
            System.arraycopy(decryptedBytes, 0, b, off, decryptedBytes.length);
            return size;
        }

        @Override
        public void close() throws IOException {
            cos.close();
        }
    }

    // EncryptionParameters.APR2011_743
    static final EncryptionParameters NTRU_PARAMS =
            new EncryptionParameters(1499, 2048, 79, 79, 0, 256, 13, 17, 19, true, new byte[] {0, 6, 5}, true, false, "SHA-512");

    public static final NtruEncrypt NTRU = new NtruEncrypt(NTRU_PARAMS);

    // max iv data size to use up to 3 cascade ciphers
    //
    // 16 - max iv size for CAST6, Twofish, Serpent
    // 32 - max iv size for Threefish-256, HC-256 and RC6
    // 128 - max iv size for Threefish-1024 or SkeinStream-1024
    public static final int MAX_IV_SIZE = 32 + 32 + 128;

    // max key data size to use up to 3 cascade ciphers
    //
    // 32 - max key size for any block cipher except SkeinStream, Threefish and RC6
    // 128 - max key size for Threefish-1024, SkeinStream-1024 or RC6-1024
    // 256 - max key size for RC6-2048
    public static final int MAX_KEYS_DATA_SIZE = 32 + 128 + 256;

    public static final Map<Class<?>, Integer> CIPHER_KEY_SIZE = new LinkedHashMap<>();
    static {
        CIPHER_KEY_SIZE.put(TwofishEngine.class, 32);
        CIPHER_KEY_SIZE.put(SerpentEngine.class, 32);
        CIPHER_KEY_SIZE.put(CAST6Engine.class, 32);

        CIPHER_KEY_SIZE.put(RC6_256_256Engine.class, 32);
        CIPHER_KEY_SIZE.put(RC6_256_512Engine.class, 64);
        CIPHER_KEY_SIZE.put(RC6_256_1024Engine.class, 128);
        CIPHER_KEY_SIZE.put(RC6_256_2048Engine.class, 256);

        CIPHER_KEY_SIZE.put(Threefish256Engine.class, 32);
        CIPHER_KEY_SIZE.put(Threefish512Engine.class, 64);
        CIPHER_KEY_SIZE.put(Threefish1024Engine.class, 128);

        CIPHER_KEY_SIZE.put(HC256Engine.class, 32);

        CIPHER_KEY_SIZE.put(SkeinStream256Engine.class, 32);
        CIPHER_KEY_SIZE.put(SkeinStream512Engine.class, 64);
        CIPHER_KEY_SIZE.put(SkeinStream1024Engine.class, 128);
    }

    public static final Map<Class<?>, Integer> CIPHER_IV_SIZE = new LinkedHashMap<>();
    static {
        CIPHER_IV_SIZE.put(TwofishEngine.class, 16);
        CIPHER_IV_SIZE.put(SerpentEngine.class, 16);
        CIPHER_IV_SIZE.put(CAST6Engine.class, 16);

        CIPHER_IV_SIZE.put(RC6_256_256Engine.class, 32);
        CIPHER_IV_SIZE.put(RC6_256_512Engine.class, 32);
        CIPHER_IV_SIZE.put(RC6_256_1024Engine.class, 32);
        CIPHER_IV_SIZE.put(RC6_256_2048Engine.class, 32);

        CIPHER_IV_SIZE.put(Threefish256Engine.class, 32);
        CIPHER_IV_SIZE.put(Threefish512Engine.class, 64);
        CIPHER_IV_SIZE.put(Threefish1024Engine.class, 128);

        CIPHER_IV_SIZE.put(HC256Engine.class, 32);

        CIPHER_IV_SIZE.put(SkeinStream256Engine.class, 32);
        CIPHER_IV_SIZE.put(SkeinStream512Engine.class, 64);
        CIPHER_IV_SIZE.put(SkeinStream1024Engine.class, 128);
    }

    public static final int ntruDecryptedChunkSize = 247;
    public static final int ntruEncryptedChunkSize = 2062;

    private StreamCipher encryptCipher;
    private StreamCipher decryptCipher;

    private static List<byte[]> splitToNTRUChunks(byte[] data) {
        int chunksAmount = (int)Math.ceil(data.length / (double)ntruDecryptedChunkSize);
        List<byte[]> chunks = new ArrayList<>(chunksAmount);
        for (int i = 0; i < chunksAmount; i++) {
            byte[] chunk = Arrays.copyOfRange(data, i*ntruDecryptedChunkSize, i*ntruDecryptedChunkSize + ntruDecryptedChunkSize);
            chunks.add(chunk);
        }
        return chunks;
    }

    public static byte[] encryptCipherKeys(byte[] keyData, EncryptionPublicKey publicKey, SecureRandom randomService) {
        byte[] paddedKeyData = pad(keyData, randomService);
        List<byte[]> keysDataChunks = splitToNTRUChunks(paddedKeyData);
        burn(paddedKeyData);

        List<byte[]> encryptedKeys = new ArrayList<>();
        for (byte[] key : keysDataChunks) {
            byte[] encryptedKey = CryptoService.NTRU.encrypt(key, publicKey);
            encryptedKeys.add(encryptedKey);
            burn(key);
        }

        return join(encryptedKeys.toArray(new byte[encryptedKeys.size()][]));
    }

    private static byte[] pad(byte[] data, SecureRandom randomService) {
        int chunksAmount = (int)Math.ceil(data.length / (double)ntruDecryptedChunkSize);
        int estimatedSize = ntruDecryptedChunkSize*chunksAmount;
        int paddingSize = estimatedSize - data.length;
        if (paddingSize > 0) {
            byte[] padding = new byte[paddingSize];
            randomService.nextBytes(padding);
            return join(data, padding);
        }
        return join(data);
    }

    public static byte[] join(byte[]... arrays) {
        int len = 0;
        for (byte[] bs : arrays) {
            len += bs.length;
        }
        byte[] joinedArray = new byte[len];
        int index = 0;
        for (byte[] bs : arrays) {
            System.arraycopy(bs, 0, joinedArray, index, bs.length);
            index += bs.length;
        }
        return joinedArray;
    }

    public static byte[] decryptCipherKeys(InputStream in, EncryptionKeyPair ntruKeyPair) {
        try {
            int chunksAmount = (int)Math.ceil(in.available() / (double)ntruEncryptedChunkSize);
            byte[] keysData = new byte[ntruDecryptedChunkSize*chunksAmount];
            for (int i = 0; i < chunksAmount; i++) {
                byte[] encryptedKeyData = new byte[ntruEncryptedChunkSize];
                in.read(encryptedKeyData);

                byte[] decryptedKey = CryptoService.NTRU.decrypt(encryptedKeyData, ntruKeyPair);
                System.arraycopy(decryptedKey, 0, keysData, i*ntruDecryptedChunkSize, decryptedKey.length);
                burn(decryptedKey);
            }
            return keysData;
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    public void setDecoderCiphers(List<Object> ciphers, byte[] ivData, byte[] clientKeyData) {
        ciphers = copy(ciphers);
        List<ParametersWithIV> clientKeys = createParams(clientKeyData, ivData, ciphers);

        List<StreamCipher> decryptCiphers = new ArrayList<>(ciphers.size());
        Iterator<ParametersWithIV> clientIVIterator = clientKeys.iterator();
        for (Object cipher : ciphers) {
            ParametersWithIV clientParams = clientIVIterator.next();

            if (cipher instanceof BlockCipher) {
                BlockCipher bc = (BlockCipher) cipher;
                StreamCipher decryptCipher = new CFBBlockCipher(bc, bc.getBlockSize()*8);
                decryptCipher.init(false, clientParams);
                decryptCiphers.add(decryptCipher);
            }
            if (cipher instanceof StreamCipher) {
                StreamCipher sc = (StreamCipher) cipher;
                sc.init(false, clientParams);
                decryptCiphers.add(sc);
            }
        }
        Collections.reverse(decryptCiphers);

        this.decryptCipher = new CascadeStreamCipher(decryptCiphers);
    }

    private List<Object> copy(List<Object> result) {
        List<Object> ciphers = new ArrayList<>(result.size());
        try {
            for (Object blockCipher : result) {
                Object cipher;
                if (blockCipher instanceof Class) {
                    cipher = ((Class)blockCipher).newInstance();
                } else {
                    cipher = blockCipher.getClass().newInstance();
                }
                ciphers.add(cipher);
            }
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        return ciphers;
    }

    public void setEncoderCiphers(List<Object> ciphers, byte[] keyData, byte[] ivData) {
        ciphers = copy(ciphers);

        List<ParametersWithIV> serverKeys = createParams(keyData, ivData, ciphers);

        List<StreamCipher> encryptCiphers = new ArrayList<>(ciphers.size());
        Iterator<ParametersWithIV> serverIVIterator = serverKeys.iterator();
        for (Object cipher : ciphers) {
            ParametersWithIV serverParams = serverIVIterator.next();

            if (cipher instanceof BlockCipher) {
                BlockCipher bc = (BlockCipher) cipher;
                StreamCipher encryptCipher = new CFBBlockCipher(bc, bc.getBlockSize()*8);
                encryptCipher.init(true, serverParams);
                encryptCiphers.add(encryptCipher);
            }
            if (cipher instanceof StreamCipher) {
                StreamCipher sc = (StreamCipher) cipher;
                sc.init(true, serverParams);
                encryptCiphers.add(sc);
            }
        }

        this.encryptCipher = new CascadeStreamCipher(encryptCiphers);
    }

    public void decrypt(OutputStream output, InputStream input, int size) throws IOException {
        CipherOutputStream os = new CipherOutputStream(output, decryptCipher);
        byte[] encrypted = new byte[size];
        input.read(encrypted);
        os.write(encrypted);
    }

    public InputStream getDecryptedInputStream(InputStream inputStream) {
        return new DecryptedInputStream(inputStream, decryptCipher);
    }

    public OutputStream getEncryptedOutputStream(OutputStream output) {
        return new CipherOutputStream(output, encryptCipher);
    }

    public void encrypt(OutputStream output, InputStream input) throws IOException {
        CipherOutputStream os = new CipherOutputStream(output, encryptCipher);
        byte[] buf = new byte[input.available()];
        input.read(buf);
        os.write(buf);
        burn(buf);
    }

    private static void burn(byte[] buffer) {
        Arrays.fill(buffer, (byte)0);
    }

    private List<ParametersWithIV> createParams(byte[] keyData, byte[] ivData, List<Object> ciphers) {
        List<ParametersWithIV> params = new ArrayList<>(ciphers.size());
        int keyIndex = 0;
        int ivIndex = 0;
        for (Object blockCipher : ciphers) {
            int keySize = CIPHER_KEY_SIZE.get(blockCipher.getClass());

            byte[] password = Arrays.copyOfRange(keyData, keyIndex, keyIndex + keySize);
            keyIndex += password.length;

            int ivSize = CIPHER_IV_SIZE.get(blockCipher.getClass());
            byte[] iv = Arrays.copyOfRange(ivData, ivIndex, ivIndex + ivSize);
            ivIndex += iv.length;

            KeyParameter kp = new KeyParameter(password);
            ParametersWithIV piv = new ParametersWithIV(kp, iv);
            params.add(piv);
            
            // copied in KeyParameter
            burn(password);
        }
        return params;
    }

}