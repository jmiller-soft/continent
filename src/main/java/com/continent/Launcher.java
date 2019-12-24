package com.continent;

import com.continent.container.ContainerConsole;

import java.io.IOException;
import java.util.concurrent.ExecutionException;

public class Launcher {

    public static void main(String[] args) throws IOException, InterruptedException, ExecutionException {
        if (args[0].equals("vpn")) {
            VPNConsole console = new VPNConsole();
            console.init(args);
        }
        if (args[0].equals("container")) {
            ContainerConsole cipher = new ContainerConsole();
            cipher.init(args);
        }
    }

}
