package com.continent.service;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.StreamCipher;

import java.util.*;

public class CombinationsGenerator {

    private static final List<Object> CIPHERS = new ArrayList<Object>();
    static {
        for (Class<?> cipher : CryptoService.CIPHER_KEY_SIZE.keySet()) {
            try {
                Object instance = cipher.newInstance();
                CIPHERS.add(instance);
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
    }

    public List<List<Object>> generate() {
        return generate(false);
    }

    public List<List<Object>> generate(boolean allowDuplications) {
        List<List<Object>> combinations = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            List<Object> attempt = new ArrayList<>();
            possibleCiphers(i+1, CIPHERS, attempt, combinations, allowDuplications);
        }
        return combinations;
    }
    
    public int countCombinations(int ciphersAmount) {
        List<Object> attempt = new ArrayList<>();
        List<List<Object>> combinations = new ArrayList<>();
        possibleCiphers(ciphersAmount, CIPHERS, attempt, combinations, false);
        return combinations.size();
    }
    
    public List<Object> getCiphers(int index, int ciphersAmount) {
        List<Object> attempt = new ArrayList<>();
        List<List<Object>> combinations = new ArrayList<>();
        possibleCiphers(ciphersAmount, CIPHERS, attempt, combinations, false);
        return combinations.get(index);
    }
    
    public List<Object> selectRandom(Random randomGenerator, int ciphersAmount) {
        List<Object> attempt = new ArrayList<>();
        List<List<Object>> combinations = new ArrayList<>();
        possibleCiphers(ciphersAmount, CIPHERS, attempt, combinations, false);
        
        int index = randomGenerator.nextInt(combinations.size());
        return combinations.get(index);
    }
    
    public static void main(String[] args) {
        CombinationsGenerator cg = new CombinationsGenerator();
        
        cg.selectRandom(new Random(), 3);
        List<List<Object>> s = cg.generate(true);
        System.out.println(s.size());
//        System.out.println(cg.countCombinations(3));
//        for (List<Object> list : s) {
//            String s1 = list.stream().map(x -> {
//                if (x instanceof BlockCipher) {
//                    return ((BlockCipher)x).getAlgorithmName() + ", ";
//                }
//                if (x instanceof StreamCipher) {
//                    return ((StreamCipher)x).getAlgorithmName() + ", ";
//                }
//                return "";
//            }).reduce("", String::concat);
//            System.out.println(s1);
//        }
    }
    
    private static void possibleCiphers(int maxLength, Collection<Object> set, List<Object> curr, List<List<Object>> combinations, boolean allowDuplications) {
        if(curr.size() == maxLength) {
            if (allowDuplications) {
                combinations.add(curr);
            } else {
                StringBuilder sb = new StringBuilder();
                for (Object x : curr) {
                    if (x instanceof BlockCipher) {
                        sb.append(((BlockCipher)x).getAlgorithmName());
                    }
                    if (x instanceof StreamCipher) {
                        sb.append(((StreamCipher)x).getAlgorithmName());
                    }
                }

                String s = sb.toString();
                int threefishMatches = s.split("Threefish").length;
                int rc6Matches = s.split("RC6").length;
                int skeinStreamMatches = s.split("SkeinStream").length;

                Set<Object> names = new LinkedHashSet<>(curr);
                if (names.size() == maxLength
                        && rc6Matches <= 2
                        && skeinStreamMatches <= 2
                        && threefishMatches <= 2
                        && (!(skeinStreamMatches == 2 && threefishMatches == 2))) {
                    combinations.add(curr);
                }
            }
        } else {
            for(Object cipher : set) {
                List<Object> oldCurr = new ArrayList<>(curr);
                try {
                    curr.add(cipher);
                } catch (Exception e) {
                    throw new IllegalStateException(e);
                }
                possibleCiphers(maxLength, set, curr, combinations, allowDuplications);
                curr = oldCurr;
            }
        }
    }
    
}
