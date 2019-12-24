package com.continent.codec;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import org.bouncycastle.jcajce.provider.digest.Skein.DigestSkein256;
import org.junit.Test;

import io.netty.buffer.ByteBufUtil;



public class TwofishTest {

    @Test
    public void test() throws IOException {
        byte[] in = ByteBufUtil.decodeHexDump("000000000000000000000000000000000000000000000000");
        
        DigestSkein256 s = new DigestSkein256(256);
        s.update(in, 0, in.length);
        byte[] out = s.digest();
        
        System.out.println(ByteBufUtil.hexDump(out));
    }

    protected byte[] convert(long[] three_256_01_key) {
        byte[] key;
        ByteBuffer t = ByteBuffer.allocate(three_256_01_key.length * 8);
        t.order(ByteOrder.LITTLE_ENDIAN);
        for (long l : three_256_01_key) {
            t.putLong(l);
        }
        System.out.println(ByteBufUtil.hexDump(t.array()));
        key = t.array();
        return key;
    }
    
}
