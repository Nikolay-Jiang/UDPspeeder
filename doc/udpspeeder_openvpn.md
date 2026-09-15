
# UDPspeeder + openvpn config guide
![image_vpn](/images/en/udpspeeder+openvpn3.PNG)

# UDPspeeder command

#### run at server side
```
./speederv2 -s -l0.0.0.0:8855 -r 127.0.0.1:7777 -f20:10 -k 00112233445566778899aabbccddeeff
```

#### run at client side
assume server ip is 45.66.77.88
```
./speederv2 -c -l0.0.0.0:3333 -r 45.66.77.88:8855 -f20:10 -k 00112233445566778899aabbccddeeff
```

`-k`/`--key` must be **exactly 32 ASCII hex characters** and **identical on both
sides**. The key authenticates the tunnel; it does not encrypt, and a peer with a
different key (including an old passphrase) is rejected. Replace the example key
above with your own 32-hex value before use.

### Encryption (optional, V3)

The default commands above use obfuscation + SipHash authentication and do
**not** encrypt. To turn on real data-plane encryption, add the same
`--cipher xchacha20-ietf-poly1305` to **both** the server and the client command
line, and the same `--pad` value if you use padding:

```
# server
./speederv2 -s -l0.0.0.0:8855 -r 127.0.0.1:7777 -f20:10 \
    -k 00112233445566778899aabbccddeeff --cipher xchacha20-ietf-poly1305

# client
./speederv2 -c -l0.0.0.0:3333 -r 45.66.77.88:8855 -f20:10 \
    -k 00112233445566778899aabbccddeeff --cipher xchacha20-ietf-poly1305
```

A peer that does not use the same `--cipher` and `--pad` is rejected: in
port-range mode the handshake refuses it, and in normal mode its packets are
dropped and logged as `auth_drop: plane=...`. Cipher mode adds 40 bytes per
packet (24-byte nonce + 16-byte tag, replacing the 8-byte SipHash data-plane
tag). `--pad 32` adds a 1-byte `pad_len` plus up to 64 authenticated pad bytes
and requires `--cipher`. OpenVPN's own encryption is independent of this
switch; enabling `--cipher` does not change how OpenVPN encrypts the inner
traffic.

# openvpn config

#### client side config
```
client
dev tun100
proto udp

remote 127.0.0.1 3333
resolv-retry infinite 
nobind 
persist-key 
persist-tun  

ca /root/add-on/openvpn/ca.crt
cert /root/add-on/openvpn/client.crt
key /root/add-on/openvpn/client.key

keepalive 3 20
verb 3
mute 20

comp-lzo no

fragment 1200       ##### very important    you can turn it up a bit. but, the lower the safer
mssfix 1200         ##### very important

sndbuf 2000000      ##### important
rcvbuf 2000000      ##### important
txqueuelen 4000     ##### suggested
```


#### server side config
```
local 0.0.0.0
port 7777 
proto udp
dev tun 

ca /etc/openvpn/easy-rsa/2.0/keys/ca.crt
cert /etc/openvpn/easy-rsa/2.0/keys/server.crt
key /etc/openvpn/easy-rsa/2.0/keys/server.key
dh /etc/openvpn/easy-rsa/2.0/keys/dh1024.pem

server 10.222.2.0 255.255.255.0 
ifconfig 10.222.2.1 10.222.2.6

client-to-client
duplicate-cn 
keepalive 10 60 

max-clients 50

persist-key
persist-tun

status /etc/openvpn/openvpn-status.log

verb 3
mute 20  

comp-lzo no

fragment 1200       ##### very important    you can turn it up a bit. but, the lower the safer
mssfix 1200         ##### very important

sndbuf 2000000      ##### important
rcvbuf 2000000      ##### important
txqueuelen 4000     ##### suggested
```

##### Note:
If you use the `redirect-gateway` option of OpenVPN, you may need to add a route exception for your remote server ip at client side.Otherwise OpenVPN may hijack UDPspeeder 's traffic.

For example, depend on your network environment, the command may looks like:
```
ip route add 44.55.66.77 via 44.55.66.1
```
or

```
ip route add 44.55.66.77 dev XXX
```
(run at client side)

##### Other Info
You can also use tinyFecVPN,a lightweight VPN with build-in FEC support:

https://github.com/wangyu-/tinyFecVPN
