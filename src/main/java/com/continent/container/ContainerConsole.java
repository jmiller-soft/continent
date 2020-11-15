package com.continent.container;

import com.continent.engine.skein.SkeinDigest;
import com.continent.random.NativeJitterGenerator;
import com.continent.random.RandomDelegator;
import com.continent.service.CryptoService;
import net.sf.ntru.encrypt.EncryptionKeyPair;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.*;

public class ContainerConsole {

    public void init(String[] args) throws IOException {
        List<String> params = new ArrayList<String>(Arrays.asList(args));

        Map<String, KeyGenerator> digestsMap = new HashMap<>();
        digestsMap.put("1", new SkeinKeyGenerator(SkeinDigest.SKEIN_256));
        digestsMap.put("2", new SkeinKeyGenerator(SkeinDigest.SKEIN_512));
        digestsMap.put("3", new SkeinKeyGenerator(SkeinDigest.SKEIN_1024));
        digestsMap.put("4", new Lyra2KeyGenerator(256));
        digestsMap.put("5", new Lyra2KeyGenerator(512));
        digestsMap.put("6", new Lyra2KeyGenerator(1024));

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
            System.out.println("  -c{abcdefghijklmn} : set ciphers used for encryption, from 1 to 3 ciphers in any combination");
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
            System.out.println("  -d{1234567} : set digest used for key generation");
            System.out.println("     1: Skein-256 ");
            System.out.println("     2: Skein-512 ");
            System.out.println("     3: Skein-1024 ");
            System.out.println("     4: Lyra2: 256 columns ");
            System.out.println("     5: Lyra2: 512 columns ");
            System.out.println("     6: Lyra2: 1024 columns ");
            System.out.println("  -v{Size}[b|k|m|g] : create volumes");
            System.out.println("  -otp{Path} : set path to one-time pad key file");
            System.out.println("  -otpc{Path} : set path to compressed one-time pad key file");
            System.out.println("  -otpm{1..100} : set skein hash rounds multiplier applied to one-time pad generation");
            System.out.println("  -pim : Personal Iterations Multiplier should be entered in console");
            System.out.println("  -pim{10..9999} : set Personal Iterations Multiplier");
            System.out.println("  -p : password should be entered in console");
            System.out.println("  -p{Password} : set Password");
            System.out.println("  -pbk{Path} : set path to NTRU public key container");
            System.out.println("  -pvk{Path} : set path to NTRU private key container");
            System.out.println("  -o{Directory} : set Output directory");
            System.out.println("");
            
            return;
        }
        
        if (params.contains("u")) {
            System.out.println("Usage examples:");
            System.out.println("");
            System.out.println("  continent.jar container e -cfkn -d3 -p Z:\\container.dat Z:\\my-files");
            System.out.println("");
            System.out.println("  Files encrypted in cascade mode: RC6-1024 > HC-256 > SkeinStream-1024");
            System.out.println("  Password entered in console. Encryption keys derived from Skein-1024 hash ");
            System.out.println("  with 83886080 rounds by default");
            System.out.println("");
            System.out.println("");
            System.out.println("  continent.jar container e -cfkn -d5 -pmy_password Z:\\container.dat Z:\\my-files");
            System.out.println("");
            System.out.println("  Files encrypted in cascade mode: RC6-1024 > HC-256 > SkeinStream-1024");
            System.out.println("  Defined password is 'my_password'. Encryption keys derived from Lyra2 password hashing scheme ");
            System.out.println("  with 512 columns and time cost = 80 by default");
            System.out.println("");
            System.out.println("");
            System.out.println("  continent.jar container e -cfkn -d1 -pim521 -p Z:\\container.dat Z:\\my-files");
            System.out.println("");
            System.out.println("  Files encrypted in cascade mode: RC6-1024 > HC-256 > SkeinStream-1024");
            System.out.println("  Password entered in console. Encryption keys derived from Skein-256 hash ");
            System.out.println("  with 546308096 rounds calculated with defined pim");
            System.out.println("");
            System.out.println("");
            System.out.println("  continent.jar container d -d1 -p -oZ:\\my-files Z:\\container.dat");
            System.out.println("");
            System.out.println("  Files decrypted with password entered in console.");
            System.out.println("  Encryption keys derived using Skein-256 hash with 83886080 rounds by default.");
            System.out.println("");
            System.out.println("");
            System.out.println("  continent.jar container g -pbkZ:\\public.key -pvkZ:\\private.key");
            System.out.println("");
            System.out.println("  Generate public and private keys.");
            System.out.println("");
            System.out.println("");
            System.out.println("  continent.jar container e -cfkn -pbkZ:\\public.key Z:\\container.dat Z:\\my-files");
            System.out.println("");
            System.out.println("  Files encrypted in cascade mode: RC6-1024 > HC-256 > SkeinStream-1024");
            System.out.println("  Encryption keys encrypted with public key.");
            System.out.println("");
            System.out.println("");
            System.out.println("  continent.jar container d -pbkZ:\\public.key -pvkZ:\\private.key -oZ:\\my-files Z:\\container.dat");
            System.out.println("  Files decrypted with defined public key.");
            System.out.println("");
            System.out.println("");
            System.out.println("  continent.jar container e -otpm3 -otpcZ:\\key.dat Z:\\container.dat Z:\\my-files");
            System.out.println("");
            System.out.println("  Files encrypted with one-time pad. One-time pad generated using SkeinPRNG ");
            System.out.println("  with increased 216 rounds. One-time pad stored in compressed format.");
            System.out.println("");
            System.out.println("");
            System.out.println("  continent.jar container d -otpcZ:\\key.dat -oZ:\\my-files Z:\\container.dat");
            System.out.println("");
            System.out.println("  Files decrypted with one-time pad in compressed format.");
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

            NativeJitterGenerator random = new NativeJitterGenerator();
            EncryptionKeyPair e = CryptoService.NTRU.generateKeyPair(new RandomDelegator(random), true);

            Files.write(Paths.get(publicKeyPath), e.getPublic().getEncoded(), StandardOpenOption.CREATE_NEW);
            Files.write(Paths.get(privateKeyPath), e.getPrivate().getEncoded(), StandardOpenOption.CREATE_NEW);
            random.shutdown();
            System.out.println("Public and private keys have been successfully generated!");
            return;
        }

        if (params.contains("d")) {
            byte[] password = null;
            byte[] publicKey = null;
            byte[] privateKey = null;
            String outputDir = null;
            int iterations = 0;
            String otpPath = null;
            boolean otpCompressed = false;
            KeyGenerator keyGenerator = null;
            for (String param : params) {
                if (param.startsWith("-otp") && !param.startsWith("-otpc")) {
                    if (password != null) {
                        System.err.println("One-time pad can't be used when password setting is defined");
                        return;
                    }
                    if (publicKey != null) {
                        System.err.println("One-time pad can't be used when public key setting is defined");
                        return;
                    }

                    otpPath = param.replace("-otp", "");
                }
                if (param.startsWith("-otpc")) {
                    if (password != null) {
                        System.err.println("One-time pad can't be used when password setting is defined");
                        return;
                    }
                    if (publicKey != null) {
                        System.err.println("One-time pad can't be used when public key setting is defined");
                        return;
                    }

                    otpPath = param.replace("-otpc", "");
                    otpCompressed = true;
                }
                if (param.startsWith("-p")
                        && !param.startsWith("-pim")
                            && !param.startsWith("-pbk")
                                && !param.startsWith("-pvk")) {
                    if (publicKey != null) {
                        System.err.println("Password can't be used when public key setting is defined");
                        return;
                    }
                    if (otpPath != null) {
                        System.err.println("Password can't be used when one-time pad setting is defined");
                        return;
                    }

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
                    if (otpPath != null) {
                        System.err.println("Public key can't be used when one-time pad setting is defined");
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

                if (param.startsWith("-o") && !param.startsWith("-otp") && !param.startsWith("-otpc")) {
                    outputDir = param.replace("-o", "") + "\\";
                }
                if (param.startsWith("-d")) {
                    if (publicKey != null) {
                        System.err.println("Digest can't be used when public key setting is defined");
                        return;
                    }
                    if (otpPath != null) {
                        System.err.println("Digest can't be used when one-time pad setting is defined");
                        return;
                    }

                    String privateKeyPath = param.replace("-d", "");
                    keyGenerator = digestsMap.get(privateKeyPath);
                    iterations = 80;
                }
                if (param.startsWith("-pim")) {
                    if (iterations == 0) {
                        throw new IllegalArgumentException("Digest algorithm is not defined!");
                    }
                    if (publicKey != null) {
                        System.err.println("PIM can't be used when public key setting is defined");
                        return;
                    }
                    if (otpPath != null) {
                        System.err.println("PIM can't be used when one-time pad setting is defined");
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
                    if (Integer.valueOf(pim) < 10 || Integer.valueOf(pim) > 9999) {
                        System.err.println("PIM should be in range between 10 and 9999");
                        return;
                    }

                    iterations = Integer.valueOf(pim);
                }
            }
            
            String encryptedFile = args[args.length - 1];

            if (publicKey != null) {
                ContainerDecryptor.NTRUContainerDecryptor c = new ContainerDecryptor.NTRUContainerDecryptor();
                c.setEncryptedFilePath(Paths.get(encryptedFile));
                c.setOutputDir(outputDir);
                c.setPrivateKey(privateKey);
                c.setPublicKey(publicKey);
                c.decrypt();
                Arrays.fill(privateKey, (byte) 0);
            } else if (password != null) {
                ContainerDecryptor.PasswordContainerDecryptor c = new ContainerDecryptor.PasswordContainerDecryptor();
                c.setKeyGenerator(keyGenerator);
                c.setIterations(iterations);
                c.setEncryptedFilePath(Paths.get(encryptedFile));
                c.setPassword(password);
                c.setOutputDir(outputDir);
                c.decrypt();
                Arrays.fill(password, (byte) 0);
            } else if (otpPath != null) {
                ContainerDecryptor.OTPContainerDecryptor c = new ContainerDecryptor.OTPContainerDecryptor();
                c.setOutputDir(outputDir);
                c.setOtpFilePath(Paths.get(otpPath));
                c.setEncryptedFilePath(Paths.get(encryptedFile));
                c.setCompressed(otpCompressed);
                c.decrypt();
            } else {
                System.err.println("Decryption method is not defined");
            }
        }

        if (params.contains("e")) {
            List<Object> ciphers = new ArrayList<>();
            byte[] password = null;
            byte[] publicKey = null;
            int iterations = 0;
            String otpPath = null;
            Long volumeSize = null;
            int roundsMultiplier = 1;
            boolean otpCompressed = false;
            KeyGenerator keyGenerator = null;
            for (String param : params) {
                if (param.startsWith("-otpm")) {
                    String sizeParam = param.replace("-otpm", "");

                    Integer m = Integer.valueOf(sizeParam);
                    if (m < 1 || m > 100) {
                        System.err.println("Skein hash rounds multiplier should be in range between 1 and 100");
                        return;
                    }

                    roundsMultiplier = Integer.valueOf(sizeParam);
                }
                if (param.startsWith("-v")) {
                    String sizeParam = param.replace("-v", "");
                    String sizeType = sizeParam.substring(sizeParam.length() - 1, sizeParam.length());
                    volumeSize = Long.valueOf(sizeParam.substring(0, sizeParam.length() - 1));
                    if (sizeType.equals("k")) {
                        volumeSize *= 1024;
                    } else if (sizeType.equals("m")) {
                        volumeSize *= 1024*1024;
                    } if (sizeType.equals("g")) {
                        volumeSize *= 1024*1024*1024;
                    }
                }
                if (param.startsWith("-otp") && !param.startsWith("-otpm") && !param.startsWith("-otpc")) {
                    if (!ciphers.isEmpty()) {
                        System.err.println("One-time pad can't be used when ciphers setting is defined");
                        return;
                    }
                    if (password != null) {
                        System.err.println("One-time pad can't be used when password setting is defined");
                        return;
                    }
                    if (publicKey != null) {
                        System.err.println("One-time pad can't be used when public key setting is defined");
                        return;
                    }

                    otpPath = param.replace("-otp", "");
                }
                if (param.startsWith("-otpc")) {
                    if (!ciphers.isEmpty()) {
                        System.err.println("One-time pad can't be used when ciphers setting is defined");
                        return;
                    }
                    if (password != null) {
                        System.err.println("One-time pad can't be used when password setting is defined");
                        return;
                    }
                    if (publicKey != null) {
                        System.err.println("One-time pad can't be used when public key setting is defined");
                        return;
                    }

                    otpPath = param.replace("-otpc", "");
                    otpCompressed = true;
                }
                if (param.startsWith("-p") && !param.startsWith("-pim") && !param.startsWith("-pbk")) {
                    if (publicKey != null) {
                        System.err.println("Password can't be used when public key setting is defined");
                        return;
                    }
                    if (otpPath != null) {
                        System.err.println("Password can't be used when one-time pad setting is defined");
                        return;
                    }

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
                    if (otpPath != null) {
                        System.err.println("Public key can't be used when one-time pad setting is defined");
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
                    if (otpPath != null) {
                        System.err.println("Digest can't be used when one-time pad setting is defined");
                        return;
                    }

                    String privateKeyPath = param.replace("-d", "");
                    keyGenerator = digestsMap.get(privateKeyPath);
                    iterations = 80;
                }
                if (param.startsWith("-c")) {
                    if (otpPath != null) {
                        System.err.println("Cipher can't be used when one-time pad setting is defined");
                        return;
                    }

                    String ciphersStr = param.replace("-c", "");
                    if (ciphersStr.length() > 3) {
                        throw new IllegalArgumentException("Cipher cascade size is limited to 3!");
                    }

                    for (int i = 0; i < ciphersStr.length(); i++) {
                        String name = String.valueOf(ciphersStr.charAt(i));
                        Class<?> cipher = ContainerSupport.CIPHERS.get(name);
                        ciphers.add(cipher);
                    }
                }
                if (param.startsWith("-pim")) {
                    if (iterations == 0) {
                        throw new IllegalArgumentException("Digest algorithm is not defined!");
                    }
                    if (publicKey != null) {
                        System.err.println("PIM can't be used when public key setting is defined");
                        return;
                    }
                    if (otpPath != null) {
                        System.err.println("PIM can't be used when one-time pad setting is defined");
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
                    iterations = Integer.valueOf(pim);
                }
            }

            if (publicKey == null && iterations == 0 && otpPath == null) {
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
            List<Path> inputPaths = new ArrayList<Path>();
            for (int j = encryptedFileIndex+1; j < args.length; j++) {
                String inputFile = args[j];
                Path inputChannel = Paths.get(inputFile);
                inputPaths.add(inputChannel);
            }

            if (publicKey != null) {
                ContainerEncryptor.NTRUContainerEncryptor c = new ContainerEncryptor.NTRUContainerEncryptor();
                c.setInputFiles(inputPaths);
                c.setEncryptedFilePath(Paths.get(encryptedFile));
                c.setVolumeSize(volumeSize);
                c.setCiphers(ciphers);
                c.setPublicKey(publicKey);
                c.encrypt();
            } else if (password != null) {
                ContainerEncryptor.PasswordContainerEncryptor c = new ContainerEncryptor.PasswordContainerEncryptor();
                c.setKeyGenerator(keyGenerator);
                c.setInputFiles(inputPaths);
                c.setEncryptedFilePath(Paths.get(encryptedFile));
                c.setVolumeSize(volumeSize);
                c.setCiphers(ciphers);
                c.setIterations(iterations);
                c.setPassword(password);
                c.encrypt();
                Arrays.fill(password, (byte) 0);
            } else if (otpPath != null) {
                ContainerEncryptor.OTPContainerEncryptor c = new ContainerEncryptor.OTPContainerEncryptor();
                c.setInputFiles(inputPaths);
                c.setEncryptedFilePath(Paths.get(encryptedFile));
                c.setVolumeSize(volumeSize);
                c.setOtpFilePath(Paths.get(otpPath));
                c.setRoundsMultiplier(roundsMultiplier);
                c.setCompressed(otpCompressed);
                c.encrypt();
            } else {
                System.err.println("Encryption method is not defined");
            }
        }
    }

}
