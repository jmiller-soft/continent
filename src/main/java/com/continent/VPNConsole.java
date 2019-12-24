package com.continent;

import com.continent.client.ProxyClient;
import com.continent.server.ProxyServer;
import com.continent.service.AuthKeyGenerator;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutionException;

public class VPNConsole {

    public void init(String[] args) throws IOException, InterruptedException, ExecutionException {
        List<String> params = new ArrayList<String>(Arrays.asList(args));

        Collections.sort(params);

        if (params.contains("vpn") && params.size() == 1) {
            System.out.println("Usage: continent.jar vpn <command> [<path to config file>]");
            System.out.println("");
            System.out.println("<Commands>");
            System.out.println("  g : Generate client/server keys");
            System.out.println("  s : Start server");
            System.out.println("  c : Start client");
            System.out.println("");
            return;
        }
        
        if (params.contains("g")) {
            AuthKeyGenerator ag = new AuthKeyGenerator();
            ag.init();
            return;
        }

        if (params.contains("s")) {
            ProxyServer server = new ProxyServer();
            server.init(args[2]);
            return;
        }

        if (params.contains("c")) {
            ProxyClient client = new ProxyClient();
            client.init(new File(args[2]));
            return;
        }
    }

}
