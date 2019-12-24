package com.continent.container;

import com.continent.random.FortunaGenerator;
import com.continent.random.RandomDelegator;
import com.continent.random.entropy.JitterEntropy;
import com.continent.service.CryptoService;
import net.sf.ntru.encrypt.EncryptionKeyPair;
import org.bouncycastle.crypto.Digest;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class ContainerConsole {

    public void init(String[] args) throws IOException {
        List<String> params = new ArrayList<String>(Arrays.asList(args));

        Collections.sort(params);

        if (params.contains("container") && params.size() == 1) {
            System.out.println("Usage: continent.jar container <command> [<switches>...] <encrypted_file> [<file_names>...]");
            System.out.println("");
            System.out.println("<Commands>");
            System.out.println("  e : Encrypt container");
            System.out.println("  d : Decrypt container");
            System.out.println("  g : Generate public and private keys");
            System.out.println("  u : Show usage examples");
            System.out.println("");
            System.out.println("<Switches>");
            System.out.println("  -c{abcdefghijklmn} : ciphers used for encryption, from 1 to 3 ciphers in any combination");
            System.out.println("     a: Twofish ");
            System.out.println("     b: Serpent ");
            System.out.println("     c: CAST6 ");
            System.out.println("     d: RC6-256 ");
            System.out.println("     e: RC6-512 ");
            System.out.println("     f: RC6-1024 ");
            System.out.println("     g: RC6-2048 ");
            System.out.println("     h: Threefish-256 ");
            System.out.println("     i: Threefish-512 ");
            System.out.println("     j: Threefish-1024 ");
            System.out.println("     k: HC-256 ");
            System.out.println("     l: SkeinStream-256 ");
            System.out.println("     m: SkeinStream-512 ");
            System.out.println("     n: SkeinStream-1024 ");
            System.out.println("  -d{1234} : digest");
            System.out.println("     1: RIPEMD160 ");
            System.out.println("     2: Skein-256 ");
            System.out.println("     3: Skein-512 ");
            System.out.println("     4: Skein-1024 ");
            System.out.println("  -pim : Personal Iterations Multiplier should be entered in console");
            System.out.println("  -pim{100..9999} : set Personal Iterations Multiplier");
            System.out.println("  -p : password should be entered in console");
            System.out.println("  -p{Password} : set Password");
            System.out.println("  -pbk{Path} : set Public key container");
            System.out.println("  -pvk{Path} : set Private key container");
            System.out.println("  -o{Directory} : set Output directory");
            System.out.println("");
            
            return;
        }
        
        if (params.contains("u")) {
            System.out.println("Usage examples:");
            System.out.println("  cipher.jar container e -cfkn -d4 -p out_file Z:\\myphoto.jpg");
            System.out.println("");
            System.out.println("  File encrypted in cascade mode: RC6-1024 > HC-256 > SkeinStream-1024");
            System.out.println("  Password entered in console. Encryption keys derived using Skein-1024 hash ");
            System.out.println("  with 500000 iterations by default");
            System.out.println("");
            System.out.println("  cipher.jar container e -cfkn -d2 -pmy_password out_file Z:\\myphoto.jpg");
            System.out.println("");
            System.out.println("  File encrypted in cascade mode: RC6-1024 > HC-256 > SkeinStream-1024");
            System.out.println("  Defined password is 'my_password'. Encryption keys derived using Skein-256 hash ");
            System.out.println("  with 500000 iterations by default");
            System.out.println("");
            System.out.println("  cipher.jar container e -cfkn -d2 -pim521 -p out_file Z:\\myphoto.jpg");
            System.out.println("");
            System.out.println("  File encrypted in cascade mode: RC6-1024 > HC-256 > SkeinStream-1024");
            System.out.println("  Password entered in console. Encryption keys derived using Skein-256 hash ");
            System.out.println("  with 536000 iterations calculated with defined pim");
            System.out.println("");
            System.out.println("  cipher.jar container g -pbkZ:\\public.key -pvkZ:\\private.key");
            System.out.println("");
            System.out.println("  Generate public and private keys.");
            System.out.println("");
            return;
        }

        if (params.contains("g")) {
            String publicKeyPath = null;
            String privateKeyPath = null;
            for (String param : params) {
                if (param.startsWith("-pbk")) {
                    publicKeyPath = param.replace("-pbk", "");
                }
                if (param.startsWith("-pvk")) {
                    privateKeyPath = param.replace("-pvk", "");
                }
            }
            if (publicKeyPath == null) {
                throw new IllegalArgumentException("Public key is not defined!");
            }
            if (privateKeyPath == null) {
                throw new IllegalArgumentException("Private key is not defined!");
            }


            JitterEntropy entropy = new JitterEntropy();
            ByteBuffer byteBuffer = ByteBuffer.allocate(1024);
            entropy.fill(byteBuffer);
            FortunaGenerator random = new FortunaGenerator(byteBuffer.array());
            EncryptionKeyPair e = CryptoService.NTRU.generateKeyPair(new RandomDelegator(random), true);

            Files.write(Paths.get(publicKeyPath), e.getPublic().getEncoded(), StandardOpenOption.CREATE_NEW);
            Files.write(Paths.get(privateKeyPath), e.getPrivate().getEncoded(), StandardOpenOption.CREATE_NEW);
            System.out.println("Public and private keys have been successfully generated!");
            return;
        }

        if (params.contains("d")) {
            List<Digest> digests = new ArrayList<Digest>(CascadeFileCipher.digest2iterations.keySet());
            byte[] password = null;
            byte[] publicKey = null;
            byte[] privateKey = null;
            String outputDir = null;
            Digest digest = null;
            Integer iterations = null;
            for (String param : params) {
                if (param.startsWith("-p")
                        && !param.startsWith("-pim")
                            && !param.startsWith("-pbk")
                                && !param.startsWith("-pvk")) {
                    String pass = param.replace("-p", "");
                    if (pass.isEmpty()) {
                        pass = new String(System.console().readPassword("Enter password: "));
                    }
                    password = pass.getBytes(StandardCharsets.UTF_8);
                    if (password.length == 0) {
                        System.err.println("Password can't be empty");
                        return;
                    }
                }
                if (param.startsWith("-pbk")) {
                    if (password != null) {
                        System.err.println("Public key can't be used when password setting is defined");
                        return;
                    }

                    String publicKeyPath = param.replace("-pbk", "");
                    publicKey = Files.readAllBytes(Paths.get(publicKeyPath));
                }
                if (param.startsWith("-pvk")) {
                    if (password != null) {
                        System.err.println("Private key can't be used when password setting is defined");
                        return;
                    }

                    String privateKeyPath = param.replace("-pvk", "");
                    privateKey = Files.readAllBytes(Paths.get(privateKeyPath));
                }

                if (param.startsWith("-o")) {
                    outputDir = param.replace("-o", "") + "\\";
                }
                if (param.startsWith("-d")) {
                    if (publicKey != null) {
                        System.err.println("Digest can't be used when public key setting is defined");
                        return;
                    }
                    Integer digestIndex = Integer.valueOf(param.replace("-d", "")) - 1;
                    digest = digests.get(digestIndex);
                    iterations = CascadeFileCipher.digest2iterations.get(digest);
                }
                if (param.startsWith("-pim")) {
                    if (iterations == null) {
                        throw new IllegalArgumentException("Digest algorithm is not defined!");
                    }
                    if (publicKey != null) {
                        System.err.println("PIM can't be used when public key setting is defined");
                        return;
                    }

                    String pim = param.replace("-pim", "");
                    if (pim.isEmpty()) {
                        pim = new String(System.console().readPassword("Enter PIM: "));
                    }
                    if (pim.isEmpty()) {
                        System.err.println("PIM can't be empty");
                        return;
                    }
                    if (Integer.valueOf(pim) < 100 || Integer.valueOf(pim) > 9999) {
                        System.err.println("PIM should be in range between 100 and 9999");
                        return;
                    }

                    iterations = Integer.valueOf(pim) * 1000 + 15000;
                }
            }
            
            String encryptedFile = args[args.length - 1];

            CascadeFileCipher c = new CascadeFileCipher();
            if (password == null) {
                c.decrypt(outputDir, publicKey, privateKey, Paths.get(encryptedFile));
            } else {
                if (digest != null) {
                    c.decrypt(outputDir, password, Paths.get(encryptedFile), digest, iterations);
                } else {
                    c.decrypt(outputDir, password, Paths.get(encryptedFile));
                }
            }
        }
        
        if (params.contains("e")) {
            List<Digest> digests = new ArrayList<Digest>(CascadeFileCipher.digest2iterations.keySet());
            List<Object> ciphers = new ArrayList<>();
            byte[] password = null;
            byte[] publicKey = null;
            Digest digest = null;
            Integer iterations = null;
            for (String param : params) {
                if (param.startsWith("-p") && !param.startsWith("-pim") && !param.startsWith("-pbk")) {
                    String pass = param.replace("-p", "");
                    if (pass.isEmpty()) {
                        pass = new String(System.console().readPassword("Enter password: "));
                        String pass2 = new String(System.console().readPassword("Re-enter password: "));
                        if (!pass.equals(pass2)) {
                            System.err.println("Passwords are not equal");
                            return;
                        }
                    }
                    password = pass.getBytes(StandardCharsets.UTF_8);
                    if (password.length == 0) {
                        System.err.println("Password can't be empty");
                        return;
                    }
                }

                if (param.startsWith("-pbk")) {
                    if (password != null) {
                        System.err.println("Public key can't be used when password setting is defined");
                        return;
                    }

                    String publicKeyPath = param.replace("-pbk", "");
                    publicKey = Files.readAllBytes(Paths.get(publicKeyPath));
                }

                if (param.startsWith("-d")) {
                    if (publicKey != null) {
                        System.err.println("Digest can't be used when public key setting is defined");
                        return;
                    }

                    Integer digestIndex = Integer.valueOf(param.replace("-d", "")) - 1;
                    digest = digests.get(digestIndex);
                    iterations = CascadeFileCipher.digest2iterations.get(digest);
                }
                if (param.startsWith("-c")) {
                    String ciphersStr = param.replace("-c", "");
                    if (ciphersStr.length() > 3) {
                        throw new IllegalArgumentException("Cipher cascade size is limited to 3!");
                    }

                    for (int i = 0; i < ciphersStr.length(); i++) {
                        String name = String.valueOf(ciphersStr.charAt(i));
                        Class<?> cipher = CascadeFileCipher.CIPHERS.get(name);
                        ciphers.add(cipher);
                    }
                }
                if (param.startsWith("-pim")) {
                    if (iterations == null) {
                        throw new IllegalArgumentException("Digest algorithm is not defined!");
                    }
                    if (publicKey != null) {
                        System.err.println("PIM can't be used when public key setting is defined");
                        return;
                    }

                    String pim = param.replace("-pim", "");
                    if (pim.isEmpty()) {
                        pim = new String(System.console().readPassword("Enter PIM: "));
                    }
                    if (pim.isEmpty()) {
                        System.err.println("PIM can't be empty");
                        return;
                    }
                    iterations = Integer.valueOf(pim) * 1000 + 15000;
                }
            }

            if (publicKey == null && iterations == null) {
                throw new IllegalArgumentException("Digest algorithm is not defined!");
            }

            int encryptedFileIndex = -1;
            for (int i = 2; i < args.length; i++) {
                if (!args[i].startsWith("-")) {
                    encryptedFileIndex = i;
                    break;
                }
            }
            String encryptedFile = args[encryptedFileIndex];
            OutputStream outputStream = Files.newOutputStream(Paths.get(encryptedFile), StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);

            List<Path> inputPaths = new ArrayList<Path>();
            for (int j = encryptedFileIndex+1; j < args.length; j++) {
                String inputFile = args[j];
                Path inputChannel = Paths.get(inputFile);
                inputPaths.add(inputChannel);
            }

            CascadeFileCipher c = new CascadeFileCipher();
            if (password == null) {
                c.encrypt(outputStream, inputPaths, publicKey, ciphers);
            } else {
                c.encrypt(outputStream, inputPaths, password, ciphers, digest, iterations);
            }
        }
    }

}
