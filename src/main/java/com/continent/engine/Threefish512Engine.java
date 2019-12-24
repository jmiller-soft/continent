package com.continent.engine;

import org.bouncycastle.crypto.engines.ThreefishEngine;

public class Threefish512Engine extends ThreefishEngine {

    public Threefish512Engine() {
        super(ThreefishEngine.BLOCKSIZE_512);
    }

}
