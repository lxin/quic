all: sample_app
clean: sample_clean

INCS = -I../net/quic/uapi/
sample_app: sample_client.c sample_server.c sample_context.h
	gcc sample_client.c -o sample_client $(INCS)
	gcc sample_server.c -o sample_server $(INCS)
sample_clean:
	rm -rf sample_client sample_server
