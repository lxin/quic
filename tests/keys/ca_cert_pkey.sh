#!/bin/bash

if [ "$1" = "clean" ]; then
	rm -rf *.pem *.ext
	exit 0
fi

# create CA and install it
openssl req -newkey rsa:2048 -nodes -keyout ca-key.pem -x509 -days 365 -out ca-cert.pem -subj "/C=CN/ST=ON/L=Ottawa/O=RH/OU=NET/CN=lucien.xin@gmail.com"
if [ -d /etc/pki/ca-trust/source/anchors/ ]; then
	cp ca-cert.pem /etc/pki/ca-trust/source/anchors/ca-cert.pem
	update-ca-trust
elif [ -d /usr/local/share/ca-certificates/ ]; then
	cp ca-cert.pem /usr/local/share/ca-certificates/ca-cert.crt
	update-ca-certificates
fi

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
