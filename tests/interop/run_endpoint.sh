#!/bin/bash
set -e

# Set up the routing needed for the simulation.
/setup.sh

if [ "$ROLE" == "client" ]; then
	# Wait for the simulator to start up.
	/wait-for-it.sh sim:57832 -s -t 10
	echo "Starting QUIC client..."
	echo "Test case: $TESTCASE"
	echo "Requests: $REQUESTS"
	echo "Keylogfile: $SSLKEYLOGFILE"

	if [ "$TESTCASE" == "resumption" ] || [ "$TESTCASE" == "zerortt" ]; then
		REQ="${REQUESTS%% *}"
		echo "./interop_test -c -D /downloads -S ./session.bin -T ./tp.bin -E $TESTCASE $REQ"
		./interop_test -c -D /downloads -S ./session.bin -T ./tp.bin -E $TESTCASE $REQ

		echo "./interop_test -c -D /downloads -S ./session.bin -T ./tp.bin -E $TESTCASE \"${REQUESTS#$REQ}\""
		./interop_test -c -D /downloads -S ./session.bin -T ./tp.bin -E $TESTCASE "${REQUESTS#$REQ}"
	elif [ "$TESTCASE" == "multiconnect" ]; then
		for REQ in $REQUESTS; do
			echo "./interop_test -c -D /downloads -E $TESTCASE \"$REQ\""
			./interop_test -c -D /downloads -E $TESTCASE "$REQ"
		done
	else
		echo "./interop_test -c -D /downloads -E $TESTCASE \"$REQUESTS\""
		./interop_test -c -D /downloads -E $TESTCASE "$REQUESTS"
	fi
else
	echo "Running QUIC server."
	echo "Test case: $TESTCASE"
	echo "Keylogfile: $SSLKEYLOGFILE"

	echo "./interop_test -s -D /www -C /certs/cert.pem -P /certs/priv.key -E $TESTCASE :::443"
	./interop_test -s -D /www -C /certs/cert.pem -P /certs/priv.key -E $TESTCASE :::443
fi
