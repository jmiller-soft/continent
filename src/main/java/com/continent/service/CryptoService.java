package com.continent.service;

import com.continent.engine.*;
import com.continent.engine.rc6.RC6_256_1024Engine;
import com.continent.engine.rc6.RC6_256_2048Engine;
import com.continent.engine.rc6.RC6_256_256Engine;
import com.continent.engine.rc6.RC6_256_512Engine;
import com.continent.random.RandomService;
import com.continent.container.stream.DecryptedInputStream;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufOutputStream;
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
import org.bouncycastle.crypto.io.MacOutputStream;
import org.bouncycastle.crypto.macs.SkeinMac;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.*;

public class CryptoService {

    // EncryptionParameters.APR2011_743
    static final EncryptionParameters NTRU_PARAMS =
            new EncryptionParameters(743, 2048, 248, 220, 60, 256, 12, 27, 14, true, new byte[] {0, 7, 105}, false, false, "Skein-512-512");

    public static final NtruEncrypt NTRU = new NtruEncrypt(NTRU_PARAMS);

    // max iv data size to use up to 3 cascade ciphers
    //
    // 16 - max iv size for CAST6, Twofish, Serpent
    // 32 - max iv size for Threefish-256, HC-256 and RC6
    // 128 - max iv size for Threefish-1024 or SkeinStream-1024
    public static final int MAX_IV_SIZE = 32 + 32 + 128;
    public static final int MAC_ID_SIZE = 8;
    public static final int TUNNEL_TYPE_SIZE = 1;
    public static final int DATA_LENGTH_SIZE = 4;
    public static final int RANDOM_DATA_LENGTH_SIZE = 4;

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

    public static final int ntruDecryptedChunkSize = 106;
    public static final int ntruEncryptedChunkSize = 1022;

    private final int blockSize = 16;
    private StreamCipher encryptCipher;
    private StreamCipher decryptCipher;
    private byte[] ivData = new byte[MAX_IV_SIZE];

    private static List<byte[]> splitToNTRUChunks(byte[] data) {
        int chunksAmount = (int)Math.ceil(data.length / (double)ntruDecryptedChunkSize);
        List<byte[]> chunks = new ArrayList<>(chunksAmount);
        for (int i = 0; i < chunksAmount; i++) {
            byte[] chunk = Arrays.copyOfRange(data, i*ntruDecryptedChunkSize, i*ntruDecryptedChunkSize + ntruDecryptedChunkSize);
            chunks.add(chunk);
        }
        return chunks;
    }

    public static byte[] encryptCipherKeys(byte[] keyData, EncryptionPublicKey publicKey, RandomService randomService) {
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

    private static byte[] pad(byte[] data, RandomService randomService) {
        int chunksAmount = (int)Math.ceil(data.length / (double)ntruDecryptedChunkSize);
        int estimatedSize = ntruDecryptedChunkSize*chunksAmount;
        int paddingSize = estimatedSize - data.length;
        if (paddingSize > 0) {
            byte[] padding = new byte[paddingSize];
            randomService.getKeyGenerator().nextBytes(padding);
            return join(data, padding);
        }
        return join(data);
    }

    private static byte[] join(byte[]... arrays) {
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

    public static byte[] decryptCipherKeys(ByteBuffer in, EncryptionKeyPair ntruKeyPair, int chunks) {
        byte[] keysData = new byte[ntruDecryptedChunkSize*chunks];
        for (int i = 0; i < chunks; i++) {
            byte[] encryptedKeyData = new byte[ntruEncryptedChunkSize];
            in.get(encryptedKeyData);

            byte[] decryptedKey = CryptoService.NTRU.decrypt(encryptedKeyData, ntruKeyPair);
            System.arraycopy(decryptedKey, 0, keysData, i*ntruDecryptedChunkSize, decryptedKey.length);
            Arrays.fill(decryptedKey, (byte) 0);
        }
        return keysData;
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
                StreamCipher decryptCipher = new CFBBlockCipher(bc, blockSize*8);
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

    public void setEncoderCiphers(List<Object> ciphers, RandomService randomService, byte[] keyData) {
        randomService.getNonceGenerator().nextBytes(ivData);

        setEncoderCiphers(ciphers, keyData, ivData);
    }

    public void setEncoderCiphers(List<Object> ciphers, byte[] keyData, byte[] ivData) {
        this.ivData = ivData;
        ciphers = copy(ciphers);
        
        List<ParametersWithIV> serverKeys = createParams(keyData, ivData, ciphers);
        
        List<StreamCipher> encryptCiphers = new ArrayList<>(ciphers.size());
        Iterator<ParametersWithIV> serverIVIterator = serverKeys.iterator();
        for (Object cipher : ciphers) {
            ParametersWithIV serverParams = serverIVIterator.next();
            
            if (cipher instanceof BlockCipher) {
                BlockCipher bc = (BlockCipher) cipher;
                StreamCipher encryptCipher = new CFBBlockCipher(bc, blockSize*8);
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
    
    public byte[] checkSessionMac(ByteBuf in, byte[] key) {
        byte[] calculatedMac = calcMac(in.readSlice(MAX_IV_SIZE), key);
        
        byte[] mac = new byte[MAC_ID_SIZE];
        in.readBytes(mac);
        
        byte[] macPart = Arrays.copyOfRange(calculatedMac, calculatedMac.length - MAC_ID_SIZE, calculatedMac.length);
        
        if (!Arrays.equals(mac, macPart)) {
            return null;
        }
        return macPart;
    }
    
    public byte[] calcMac(ByteBuf in, byte[] key) {
        SkeinMac tagMac = new SkeinMac(SkeinMac.SKEIN_256, 256);
        tagMac.init(new KeyParameter(key));
        
        MacOutputStream os = new MacOutputStream(tagMac);
        try {
            in.readBytes(os, in.readableBytes());
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        return os.getMac();
    }

    public byte[] getIvData() {
        return ivData;
    }
    
    public void decrypt(ByteBuf output, ByteBuf input) {
        decrypt(output, input, input.readableBytes());
    }
    
    public void decrypt(ByteBuf output, ByteBuf input, int size) {
        CipherOutputStream os = new CipherOutputStream(new ByteBufOutputStream(output), decryptCipher);
        try {
            input.readBytes(os, size);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    public InputStream getDecryptedInputStream(InputStream inputStream) {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        CipherOutputStream cipherOutput = new CipherOutputStream(output, decryptCipher);
        return new DecryptedInputStream(inputStream, cipherOutput, output);
    }

    public OutputStream getEncryptedOutputStream(OutputStream output) {
        return new CipherOutputStream(output, encryptCipher);
    }

    public void encrypt(ByteBuf output, ByteBuf input) {
        CipherOutputStream os = new CipherOutputStream(new ByteBufOutputStream(output), encryptCipher);
        try {
            input.readBytes(os, input.readableBytes());
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
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
