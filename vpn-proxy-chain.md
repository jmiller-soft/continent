## How to use Continent VPN as proxy chain

Continent allows to create chain with any type of proxy - socks4/5, http, https... All traffic passes first through continent and then your proxy. Thus you behind two proxies.

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

Add your Proxy server in `portMapping` config section
Add server to `servers` config section
Add client key to `keys` config section

```yaml
port: 1023
servers:
     - "encrypted://<server ip>:<server port>"
keyRotationInterval: "3600:7200"
tcpNoDelay: true
maxWriteDelayMs: 0
key: "<client key>"
portMapping:
     1441: "proxy.com:4041" 
```

#### 5. Run VPN client

java -jar continent.jar vpn c client.yaml



#### 6. Use your proxy server

Now you can use proxy bounded to 1441 port.
