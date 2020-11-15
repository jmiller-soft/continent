package com.continent.engine;

import com.continent.engine.skein.SkeinDigest;
import org.assertj.core.api.Assertions;
import org.junit.Test;

public class CustomSkeinTest {

    @Test
    public void test() {
        test(SkeinDigest.SKEIN_1024, 80);
        test(SkeinDigest.SKEIN_512, 72);
        test(SkeinDigest.SKEIN_256, 72);
    }

    public void test(int stateSize, int rounds) {
        byte[] state = new byte[stateSize/8];
        org.bouncycastle.crypto.digests.SkeinDigest digest = new org.bouncycastle.crypto.digests.SkeinDigest(stateSize, stateSize);
        digest.update(state, 0, state.length);
        digest.doFinal(state, 0);

        byte[] newState = new byte[stateSize/8];
        SkeinDigest newDigest = new SkeinDigest(stateSize, stateSize, rounds);
        newDigest.update(newState, 0, newState.length);
        newDigest.doFinal(newState, 0);

        Assertions.assertThat(state).isEqualTo(newState);
    }


}
