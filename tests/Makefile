all: func_test perf_test sample_test ticket_test alpn_test

%_test: %_test.c
	$(CC) $^ -o $@ -lquic

perf_test: perf_test.c
	$(CC) $^ -o $@ -lquic -lgnutls

msquic_test: msquic_test.c
	$(CXX) $^ -o $@ -lmsquic -Wl,-rpath=/usr/local/lib -Wall

clean:
	rm -rf perf_test func_test sample_test ticket_test alpn_test
	rm -rf msquic_test
distclean: clean
	rm -rf keys/*.pem keys/*.ext keys/*.txt

run: all
	./runtest.sh
