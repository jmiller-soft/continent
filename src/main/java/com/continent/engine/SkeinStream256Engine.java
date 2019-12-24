package com.continent.engine;

import org.bouncycastle.crypto.digests.SkeinDigest;

public class SkeinStream256Engine extends SkeinStreamEngine {

    public SkeinStream256Engine() {
        super(SkeinDigest.SKEIN_256);
    }

}
