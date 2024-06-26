#!/bin/bash

if [ "$1" = "clean" ]; then
	rm -rf *.pem *.ext *.txt
	exit 0
fi

# create PSK files
psk_id1=test1
psk_id2=test2
psk_key1=b8d3a37be2c9a08eaf25cf6abe602ecc94417f8ba6211a58b8d0a3fb0d2e3a90
psk_key2=b8d3a37be2c9a08eaf25cf6abe602ecc94417f8ba6211a58b8d0a3fb0d2e3a91

if [ "$1" = "psk-keyring" ]; then
	# create PSK keyring
	KEYRING=`keyctl newring quic @s`
	keyctl setperm $KEYRING 0x3f1f1f1f
	keyctl link $KEYRING @u
	KEY1=$(keyctl add user $psk_id1 `echo $psk_key1 | xxd -r -p` %:quic)
	keyctl setperm $KEY1 0x3f1f1f1f
	KEY2=$(keyctl add user $psk_id2 `echo $psk_key2 | xxd -r -p` %:quic)
	keyctl setperm $KEY2 0x3f1f1f1f
	keyctl unlink $KEYRING @s
	echo "keyring $KEYRING with user keys $KEY1 and $KEY2 is created"
	exit 0
fi

cat <<EOF >client-psk.txt
$psk_id2:$psk_key2
$psk_id1:$psk_key1
EOF

cat <<EOF >server-psk.txt
$psk_id1:$psk_key1
$psk_id2:$psk_key2
EOF

# create CA
openssl req -newkey rsa:2048 -nodes -keyout ca-key.pem -x509 -days 365 -out ca-cert.pem -subj "/C=CN/ST=ON/L=Ottawa/O=RH/OU=NET/CN=lucien.xin@gmail.com"

cat > server.ext << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names
[alt_names]
DNS.1 = server.test
EOF

# create server cert and sign it
openssl req -newkey rsa:2048 -nodes -keyout server-key.pem -out server-req.pem -subj "/C=CA/ST=ON/L=Ottawa/O=RH/OU=NET/CN=lucien.xin@gmail.com"
openssl x509 -req -days 186 -set_serial 01 -in server-req.pem -out server-cert.pem -CA ca-cert.pem -CAkey ca-key.pem -extfile server.ext

# create client cert and sign it
openssl req -newkey rsa:2048 -nodes -keyout client-key.pem -out client-req.pem -subj "/C=CA/ST=ON/L=Ottawa/O=RH/OU=NET/CN=lucien.xin@gmail.com"
openssl x509 -req -days 186 -set_serial 01 -in client-req.pem -out client-cert.pem -CA ca-cert.pem -CAkey ca-key.pem
