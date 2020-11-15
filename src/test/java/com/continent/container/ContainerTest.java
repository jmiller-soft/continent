package com.continent.container;

import org.assertj.core.api.Assertions;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

public class ContainerTest {

    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    @Test
    public void testNTRU() throws IOException, NoSuchAlgorithmException {
        List<byte[]> digests = new ArrayList<>();
        Path directory = folder.newFolder().toPath();
        createTestFiles(digests, directory);

        Path keys = folder.newFolder().toPath();
        Path publicKey = keys.resolve("public.key");
        Path privateKey = keys.resolve("private.key");
        ContainerConsole c3 = new ContainerConsole();
        String params3 = "g -pbk" + publicKey + " -pvk" + privateKey;
        String[] pps3 = params3.split(" ");
        c3.init(pps3);

        Path outputDir = folder.newFolder().toPath();
        Path container = outputDir.resolve("container.dat");

        ContainerConsole c1 = new ContainerConsole();
        String params = "e -ca -pbk" + publicKey + " " + container + " " + directory;
        String[] pps = params.split(" ");
        c1.init(pps);

        Path directory2 = folder.newFolder().toPath();
        ContainerConsole c2 = new ContainerConsole();
        String params2 = "d -pbk" + publicKey + " -pvk" + privateKey + " -o" + directory2 + " " + container;
        String[] pps2 = params2.split(" ");
        c2.init(pps2);

        testDecryptedFiles(directory, digests, directory2);
    }

    @Test
    public void testPassword() throws IOException, NoSuchAlgorithmException {
        List<byte[]> digests = new ArrayList<>();
        Path directory = folder.newFolder().toPath();
        createTestFiles(digests, directory);

        Path outputDir = folder.newFolder().toPath();
        Path container = outputDir.resolve("container.dat");

        ContainerConsole c1 = new ContainerConsole();
        String params = "e -ca -d3 -p123 -pim80 " + container + " " + directory;
        String[] pps = params.split(" ");
        c1.init(pps);

        Path directory2 = folder.newFolder().toPath();
        ContainerConsole c2 = new ContainerConsole();
        String params2 = "d -d3 -p123 -pim80 -o" + directory2 + " " + container;
        String[] pps2 = params2.split(" ");
        c2.init(pps2);

        testDecryptedFiles(directory, digests, directory2);
    }

    @Test
    public void testOTP() throws IOException, NoSuchAlgorithmException {
        List<byte[]> digests = new ArrayList<>();
        Path directory = folder.newFolder().toPath();
        createTestFiles(digests, directory);

        Path outputDir = folder.newFolder().toPath();
        Path key = outputDir.resolve("random.dat");
        Path container = outputDir.resolve("container.dat");

        ContainerConsole c1 = new ContainerConsole();
        String params = "e -otpm3 -v3g -otp" + key + " " + container + " " + directory;
        String[] pps = params.split(" ");
        c1.init(pps);

        Path directory2 = folder.newFolder().toPath();
        ContainerConsole c2 = new ContainerConsole();
        String params2 = "d -otp" + key + " -o" + directory2 + " " + container;
        String[] pps2 = params2.split(" ");
        c2.init(pps2);

        testDecryptedFiles(directory, digests, directory2);
    }

    @Test
    public void testCompressedOTP() throws IOException, NoSuchAlgorithmException {
        List<byte[]> digests = new ArrayList<>();
        Path directory = folder.newFolder().toPath();
        createTestFiles(digests, directory);

        Path outputDir = folder.newFolder().toPath();
        Path key = outputDir.resolve("random.dat");
        Path container = outputDir.resolve("container.dat");

        ContainerConsole c1 = new ContainerConsole();
        String params = "e -otpm1 -v3g -otpc" + key + " " + container + " " + directory;
        String[] pps = params.split(" ");
        c1.init(pps);

        Path directory2 = folder.newFolder().toPath();
        ContainerConsole c2 = new ContainerConsole();
        String params2 = "d -otpc" + key + " -o" + directory2 + " " + container;
        String[] pps2 = params2.split(" ");
        c2.init(pps2);

        testDecryptedFiles(directory, digests, directory2);
////        String params = "e -otps1 -v3g -otpcC:\\temp\\key\\random.dat C:\\temp\\data\\memory.dmp C:\\Devel\\projects";
////        String params = "d -otpC:\\temp\\key2\\random.dat -oC:\\my-files C:\\temp\\data2\\memory.dmp";
////        String params = "d -otpG:\\key\\random.dat -oC:\\my-files C:\\temp\\data\\memory.dmp";
////        String params = "e -ca -d4 -p123 -pim100 C:\\Devel\\out_file C:\\Devel\\IntelliJ";
////        String params = "d -d4 -p123 -pim100 -oC:\\my-files C:\\Devel\\out_file";
////        String params = "g -pbkC:\\Downloads\\public4.key -pvkC:\\Downloads\\private4.key";
//        String[] pps = params.split(" ");
//        c.init(pps);

    }

    private void createTestFiles(List<byte[]> digests, Path directory) throws IOException, NoSuchAlgorithmException {
        digests.add(createFile(directory.resolve("myfile.txt")));
        Files.createDirectory(directory.resolve("1"));
        digests.add(createFile(directory.resolve("1").resolve("1.txt")));
        digests.add(createFile(directory.resolve("1").resolve("2.txt")));
        digests.add(createFile(directory.resolve("1").resolve("3.txt")));
        Files.createDirectories(directory.resolve("1").resolve("123").resolve("1"));
        Files.createDirectories(directory.resolve("1").resolve("123").resolve("2"));
        Files.createDirectories(directory.resolve("1").resolve("123").resolve("3").resolve("4"));
    }

    private void testDecryptedFiles(Path directory, List<byte[]> digests, Path directory2) throws IOException {
        Assertions.assertThat(digests.get(0)).isEqualTo(Files.readAllBytes(directory2.resolve(directory.getFileName()).resolve("myfile.txt")));
        Assertions.assertThat(digests.get(1)).isEqualTo(Files.readAllBytes(directory2.resolve(directory.getFileName()).resolve("1").resolve("1.txt")));
        Assertions.assertThat(digests.get(2)).isEqualTo(Files.readAllBytes(directory2.resolve(directory.getFileName()).resolve("1").resolve("2.txt")));
        Assertions.assertThat(digests.get(3)).isEqualTo(Files.readAllBytes(directory2.resolve(directory.getFileName()).resolve("1").resolve("3.txt")));
        Assertions.assertThat(Files.exists(directory2.resolve(directory.getFileName()).resolve("1").resolve("123").resolve("1"))).isTrue();
        Assertions.assertThat(Files.exists(directory2.resolve(directory.getFileName()).resolve("1").resolve("123").resolve("2"))).isTrue();
        Assertions.assertThat(Files.exists(directory2.resolve(directory.getFileName()).resolve("1").resolve("123").resolve("3").resolve("4"))).isTrue();
    }

    private byte[] createFile(Path file) throws IOException, NoSuchAlgorithmException {
        Path f = Files.createFile(file);
        byte[] bytes = new byte[123];
        ThreadLocalRandom.current().nextBytes(bytes);
        Files.write(f, bytes);
        return bytes;
    }

}
