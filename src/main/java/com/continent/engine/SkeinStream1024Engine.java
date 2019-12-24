package com.continent.engine;

import org.bouncycastle.crypto.digests.SkeinDigest;

public class SkeinStream1024Engine extends SkeinStreamEngine {

    public SkeinStream1024Engine() {
        super(SkeinDigest.SKEIN_1024);
    }

}
