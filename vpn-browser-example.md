## How to use Continent VPN with browser

#### Show usage help

java -jar continent.jar vpn


#### 1. Generate VPN keys per client

java -jar continent.jar vpn g

You'll get both client and server keys.

#### 2. Create `server.yaml` configuration file for VPN server

Add server key in `keys` config section

```yaml
port: <server port>
tcpNoDelay: true
maxWriteDelayMs: 0
keys:
  - "<server key for client 1>"
  - "<server key for client 2>"
```

#### 3. Run VPN server

java -jar continent.jar vpn s server.yaml

#### 4. Create `client.yaml` configuration file for VPN client

Add server to `servers` config section
Add client key to `keys` config section
In this example socks5 server run on 1023 port

```yaml
port: 1023
servers:
     - "encrypted://<server ip>:<server port>"
keyRotationInterval: "3600:7200" #key changed every randomly selected interval between 3600 and 7200 minutes
tcpNoDelay: true
maxWriteDelayMs: 0
key: "<define client key here>"
```

#### 5. Run VPN client

java -jar continent.jar vpn c client.yaml

#### 6. Run Browser with VPN client as proxy server

[ungoogled-chromium](https://ungoogled-software.github.io)

```
chromium --proxy-server="socks5://127.0.0.1:1023"
```