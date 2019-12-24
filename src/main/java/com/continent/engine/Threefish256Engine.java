package com.continent.engine;

import org.bouncycastle.crypto.engines.ThreefishEngine;

public class Threefish256Engine extends ThreefishEngine {

    public Threefish256Engine() {
        super(ThreefishEngine.BLOCKSIZE_256);
    }

}
