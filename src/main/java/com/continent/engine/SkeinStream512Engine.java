package com.continent.engine;

import org.bouncycastle.crypto.digests.SkeinDigest;

public class SkeinStream512Engine extends SkeinStreamEngine {

    public SkeinStream512Engine() {
        super(SkeinDigest.SKEIN_512);
    }

}
