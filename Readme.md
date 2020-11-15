# Continent - secure VPN proxy (client and server) and file container with military-grade encryption

## Use cases

* Encryption of TCP protocol (SSH, SMTP, IMAP ...) through port tunneling  
* Encryption of Web browsing and WebRTC session through local Socks5 proxy  

* Files encryption with one-time pad  
* Files encryption with password  
* Files encryption with NTRU public and private keys  

## Usage examples

[How to use Continent VPN with browser](vpn-browser-example.md)  

[How to use Continent VPN with Email client](vpn-email-client-example.md)  

[How to use Continent file container with password](container-password.md)  

[How to use Continent file container with public and private keys](container-ntru.md)  

[How to use Continent file container with one-time pad](container-otp.md)  

## VPN features

* VPN client exposes local Socks5 proxy  
* VPN client supports port tunneling  

* Deep Packet Inspection (DPI) resistant protocol: handshake and traffic is computationally indistinguishable from random data  
* Polymorphic protocol: random packet length, inter-arrival time and packets generation (noise)  
* Protocol masking: encrypted traffic can be wrapped up into HTTPS protocol to bypass some firewalls  
* Forward secrecy property  
* Low memory consumption: client - 32Mb, server - 256Mb  
* Cascade encryption scheme of 3 randomly selected ciphers.  
* Overall key size range is from 768 to 3328 bits.  
* Key exchange encryption cipher: 256-bit [NTRU](https://github.com/tbuktu/ntru) based on Skein-512  

## Container features

* One-time pad derived from Skein PRNG continuously seeded with Hardware RNG values  
* Password derived from Skein PRNG or Lyra2  

## Crypto engine features

* High-quality entropy gathered from [Hardware RNG based on CPU timing jitter](http://www.chronox.de/jent.html)  
* Independent Skein PRNG based random generators for Nonce and Key  
* Random generators are seeded every second  

* Encryption ciphers used in cascade encryption scheme:  

| Cipher        | Block size (bits) | Key size (bits)       | Encryption <br/> mode| Increased <br/> rounds |
| --------------| ------------------| ----------------------| ---------------------| -----------------------|
| RC6           | 256               | 256, 512, 1024, 2048  | CFB                  | 30, 38, 42, 46         |
| CAST6         | 128               | 256                   | CFB                  | -                      |
| Twofish       | 128               | 256                   | CFB                  | 24                     |
| Threefish     | 256, 512, 1024    | 256, 512, 1024        | CFB                  | -                      |
| Serpent       | 128               | 256                   | CFB                  | -                      |
| SkeinStream   | -                 | 256, 512, 1024        | Stream               | -                      |
| HC256         | -                 | 256                   | Stream               | -                      |

## Download

[continent.jar](https://github.com/jmiller-soft/continent/releases/download/1.1.0/continent.jar)

