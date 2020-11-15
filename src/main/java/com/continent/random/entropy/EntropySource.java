package com.continent.random.entropy;

import java.nio.ByteBuffer;

public interface EntropySource {

    void fill(ByteBuffer randomBytes);

    void shutdown();

}
