package com.continent.engine;

import static org.assertj.core.api.Assertions.assertThat;

import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.junit.Test;

public class SkeinStreamEngineTest {

    @Test
    public void test512() {
        SkeinStreamEngine engine = create512Engine();
        
        byte[] in = new byte[] {20, 21, 22, 23, 24, 25, 26, 27};
        byte[] out = new byte[in.length];
        engine.processBytes(in, 0, in.length, out, 0);
        
        assertThat(out).doesNotContain(in);

        SkeinStreamEngine engine2 = create512Engine();
        byte[] in2 = new byte[in.length];
        engine2.processBytes(out, 0, out.length, in2, 0);
        
        assertThat(in2).isEqualTo(in);
    }

    @Test
    public void test1024() {
        SkeinStreamEngine engine = create1024Engine();
        
        byte[] in = new byte[] {20, 21, 22, 23, 24, 25, 26, 27};
        byte[] out = new byte[in.length];
        engine.processBytes(in, 0, in.length, out, 0);
        
        assertThat(out).doesNotContain(in);

        SkeinStreamEngine engine2 = create1024Engine();
        byte[] in2 = new byte[in.length];
        engine2.processBytes(out, 0, out.length, in2, 0);
        
        assertThat(in2).isEqualTo(in);
    }
    
    @Test
    public void test256() {
        SkeinStreamEngine engine = create256Engine();
        
        byte[] in = new byte[] {20, 21, 22, 23, 24, 25, 26, 27};
        byte[] out = new byte[in.length];
        engine.processBytes(in, 0, in.length, out, 0);
        
        assertThat(out).doesNotContain(in);

        SkeinStreamEngine engine2 = create256Engine();
        byte[] in2 = new byte[in.length];
        engine2.processBytes(out, 0, out.length, in2, 0);
        
        assertThat(in2).isEqualTo(in);
    }

    protected SkeinStreamEngine create256Engine() {
        byte[] password = new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 2, 3};
        byte[] iv = new byte[] {10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 1, 2};
        
        SkeinStreamEngine engine = new SkeinStream256Engine();
        KeyParameter kp = new KeyParameter(password);
        ParametersWithIV piv = new ParametersWithIV(kp, iv);
        engine.init(true, piv);
        return engine;
    }
    
    protected SkeinStreamEngine create512Engine() {
        byte[] password = new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 2, 3,
                                      0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 2, 3};
        
        byte[] iv = new byte[] {10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 1, 2,
                                10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 1, 2};
        
        SkeinStreamEngine engine = new SkeinStream512Engine();
        KeyParameter kp = new KeyParameter(password);
        ParametersWithIV piv = new ParametersWithIV(kp, iv);
        engine.init(true, piv);
        return engine;
    }

    protected SkeinStreamEngine create1024Engine() {
        byte[] password = new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 2, 3,
                                      0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 2, 3,
                                      0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 2, 3,
                                      0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 2, 3};
        
        byte[] iv = new byte[] {10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 1, 2,
                                10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 1, 2,
                                10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 1, 2,
                                10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 1, 2};
        
        SkeinStreamEngine engine = new SkeinStream1024Engine();
        KeyParameter kp = new KeyParameter(password);
        ParametersWithIV piv = new ParametersWithIV(kp, iv);
        engine.init(true, piv);
        return engine;
    }
    
}
