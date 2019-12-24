package com.continent.random;

import static org.assertj.core.api.Assertions.assertThat;

import com.continent.engine.rc6.RC6_128Engine;
import com.continent.engine.rc6.RC6_256_256Engine;
import org.bouncycastle.crypto.prng.RandomGenerator;
import org.junit.Test;

public class FortunaGeneratorTest extends BaseRandomTest {

    @Override
    RandomGenerator createRandom(byte[] seed) {
        return new FortunaGenerator(seed);
    }
    
    @Test
    public void testBlockSize() {
        RandomGenerator random16 = new FortunaGenerator(new byte[] {1, 2, 3, 4}, new RC6_128Engine());
        assertAllBytesAreFilled(random16);
        
        RandomGenerator random32 = new FortunaGenerator(new byte[] {1, 2, 3, 4}, new RC6_256_256Engine());
        assertAllBytesAreFilled(random32);
    }

    protected void assertAllBytesAreFilled(RandomGenerator random) {
        for (int i = 1; i < 64; i++) {
            byte[] bytes = new byte[i];
            random.nextBytes(bytes);

            assertThat(bytes[bytes.length-1]).isNotZero();
        }
    }

}
