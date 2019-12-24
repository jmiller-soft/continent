package com.continent.codec;

import java.util.Arrays;

import com.continent.random.RandomDelegator;
import com.continent.random.RandomService;
import mockit.Mock;
import mockit.MockUp;

public class MockedRandomService {

    public static RandomService create() {
        new MockUp<RandomService>() {
            @Mock
            void $init() {
            }
            
            @Mock
            public RandomDelegator getNonceGenerator() {
                return new RandomDelegator(null) {
                    public void nextBytes(byte[] bytes) {
                        Arrays.fill(bytes, (byte)0);
                    };
                };
            }
        };
        
        return new RandomService();
    }
    
}
