package com.continent.container;

public interface KeyGenerator {

    byte[] generateKeyData(byte[] password, byte[] salt, int keySize, int pim);

}
