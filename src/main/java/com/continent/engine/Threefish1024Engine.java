package com.continent.engine;

import org.bouncycastle.crypto.engines.ThreefishEngine;

public class Threefish1024Engine extends ThreefishEngine {

    public Threefish1024Engine() {
        super(ThreefishEngine.BLOCKSIZE_1024);
    }

}
