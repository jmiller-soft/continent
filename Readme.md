# Continent - VPN and file container with military-grade encryption

## Use cases

* TCP protocol hiding (SSH, SMTP, IMAP ...) through port tunneling  
* Web browsing and WebRTC session hiding through local Socks5 proxy  
* Files encryption with password or NTRU public key  

## Usage examples

[How to use Continent VPN with browser](vpn-browser-example.md)  

[How to use Continent VPN with Email client](vpn-email-client-example.md)  

[How to use Continent file container](container-example.md)  

## VPN Features

* Exposes local Socks5 proxy  
* Port tunneling  

* Deep Packet Inspection (DPI) resistant protocol: handshake and traffic is computationally indistinguishable from random data  
* Polymorphic protocol: random packet length, inter-arrival time and packets generation (noise)  
* Protocol masking: encrypted traffic can be wrapped up into HTTPS protocol to bypass some firewalls  
* Forward secrecy property  
* Replay attack protection (one-time MAC per connection)  
* Low memory consumption: client - 32Mb, server - 256Mb  
* Cascade encryption scheme of 3 randomly selected ciphers.  
* Overall key size range is from 768 to 3328 bits.  
* Key exchange encryption cipher: 256-bit [NTRU](https://github.com/tbuktu/ntru)  

## Crypto engine features

* High-quality entropy gathered from [Hardware RNG based on CPU timing jitter](http://www.chronox.de/jent.html)  
* Independent random generators for Nonce and Key:  
  * Fortuna algorithm based on Skein-256 and randomly selected RC6 / CAST6 / Twofish cipher  
  * Seeded every second  

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

[continent.jar.zip (remove zip extension)](https://github.com/jmiller-soft/continent/files/3998227/continent.jar.zip)

