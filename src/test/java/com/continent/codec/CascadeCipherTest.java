package com.continent.codec;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import com.continent.engine.TwofishEngine;
import com.continent.engine.rc6.RC6_256_256Engine;
import com.continent.random.RandomService;
import com.continent.service.CryptoService;
import com.continent.service.HandshakeService;
import org.bouncycastle.crypto.engines.CAST6Engine;
import org.junit.Test;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;

public class CascadeCipherTest {

    private static final RandomService randomService = MockedRandomService.create();

    @Test
    public void testTwoInCascade() throws IOException {
        byte[] data = new byte[16];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) i;
        }
        
        byte[] encrypted = {-114, 90, 49, -117, -64, -46, -121, -2, -57, -56, -47, -53, 58, -35, -122, 30};
        List<Object> ciphers = Arrays.<Object>asList(new RC6_256_256Engine());
        testChipers(data, ciphers, encrypted, randomService);
        
        List<Object> ciphers2 = Arrays.<Object>asList(new CAST6Engine());
        byte[] encrypted2 = {-65, -104, 100, 33, 71, -112, -123, 21, 103, 31, -59, 34, -113, -18, -127, -24};
        testChipers(encrypted, ciphers2, encrypted2, randomService);
        
        List<Object> ciphers3 = Arrays.<Object>asList(new RC6_256_256Engine(), new CAST6Engine());
        testChipers(data, ciphers3, encrypted2, randomService);
    }
    
    @Test
    public void testThreeInCascade() throws IOException {
        byte[] data = new byte[16];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) i;
        }

        byte[] encrypted = {-114, 90, 49, -117, -64, -46, -121, -2, -57, -56, -47, -53, 58, -35, -122, 30};
        List<Object> ciphers = Arrays.<Object>asList(new RC6_256_256Engine());
        testChipers(data, ciphers, encrypted, randomService);
        
        List<Object> ciphers2 = Arrays.<Object>asList(new CAST6Engine());
        byte[] encrypted2 = {-65, -104, 100, 33, 71, -112, -123, 21, 103, 31, -59, 34, -113, -18, -127, -24};
        testChipers(encrypted, ciphers2, encrypted2, randomService);
        
        List<Object> ciphers3 = Arrays.<Object>asList(new TwofishEngine());
        byte[] encrypted3 = {35, 24, -125, -20, 48, -10, 19, -4, -96, -70, 12, -90, -59, 125, 109, 79};
        testChipers(encrypted2, ciphers3, encrypted3, randomService);

        
        List<Object> cascadeCiphers = Arrays.<Object>asList(new RC6_256_256Engine(), new CAST6Engine(), new TwofishEngine());
        testChipers(data, cascadeCiphers, encrypted3, randomService);
    }


    protected void testChipers(byte[] data, List<Object> ciphers, byte[] encryptedData, RandomService randomService) throws IOException {
        CryptoService ch = new CryptoService();
        
        byte[] serverKeyData = new byte[CryptoService.MAX_KEYS_DATA_SIZE];
        Arrays.fill(serverKeyData, (byte)0);

        byte[] iv = new byte[CryptoService.MAX_IV_SIZE];
        randomService.getNonceGenerator().nextBytes(iv);

        ch.setEncoderCiphers(ciphers, serverKeyData, iv);
        ch.setDecoderCiphers(ciphers, iv, serverKeyData);
        
        ByteArrayInputStream input = new ByteArrayInputStream(data);
        ByteArrayOutputStream output = new ByteArrayOutputStream();

        ch.encrypt(output, input);
        
        System.out.println(Arrays.toString(output.toByteArray()));
        assertThat(output.toByteArray()).isEqualTo(encryptedData);

        ByteArrayInputStream input2 = new ByteArrayInputStream(output.toByteArray());
        ByteArrayOutputStream output2 = new ByteArrayOutputStream();
        ch.decrypt(output2, input2, input2.available());
        assertThat(output2.toByteArray()).isEqualTo(data);
    }
    
}
