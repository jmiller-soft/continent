## How to use Continent VPN with Email client

#### Show usage help

java -jar continent.jar vpn


#### 1. Generate VPN keys per client

java -XX:CompileCommand=exclude,com/continent/random/entropy/JitterEntropy.* -jar continent.jar vpn-keys

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

java -XX:CompileCommand=exclude,com/continent/random/entropy/JitterEntropy.* -jar continent.jar vpn-server server.yaml

#### 4. Create `client.yaml` configuration file for VPN client

Add your IMAP and SMTP servers in `portMapping` config section.
Add server to `servers` config section
Add client key to `keys` config section

```yaml
port: 1023
servers:
     - "encrypted://<server ip>:<server port>"
keyRotationInterval: "3600:7200" #key changed every randomly selected interval between 3600 and 7200 minutes
tcpNoDelay: true
maxWriteDelayMs: 0
key: "<client key>"
portMapping:
     1590: "imap.myserver.com:590"
     1993: "smtp.myserver.com:993"
```

#### 5. Run VPN client

java -XX:CompileCommand=exclude,com/continent/random/entropy/JitterEntropy.* -jar continent.jar vpn-client client.yaml

#### 6. Bind email servers to local host

Add to hosts file:

127.0.0.1 imap.myserver.com
127.0.0.1 smtp.myserver.com

#### 6. Run Email client with follow settings

IMAP server:

```
imap.myserver.com:1590
```

SMTP server:

```
smtp.myserver.com:1993
```

