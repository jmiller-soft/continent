package com.continent.container;

import com.github.all3fox.lyra2.Lyra2;
import com.github.all3fox.lyra2.LyraParams;

public class Lyra2KeyGenerator implements KeyGenerator {

    private int columns;

    public Lyra2KeyGenerator(int columns) {
        this.columns = columns;
    }

    @Override
    public byte[] generateKeyData(byte[] password, byte[] salt, int keySize, int pim) {
        LyraParams params = new LyraParams(
                768, pim, 100,
                columns, "blake2b",
                128, 24,
                12
        );

        byte[] result = new byte[keySize];
        Lyra2.phs(result, password, salt, params);
        return result;
    }

}
