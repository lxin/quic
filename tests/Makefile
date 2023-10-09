all: func_test perf_test sample_test

func_test: func_test.c
	gcc func_test.c -o func_test -lquic
perf_test: perf_test.c
	gcc perf_test.c -o perf_test -lquic -lgnutls
sample_test: sample_test.c
	gcc sample_test.c -o sample_test
msquic_test: msquic_test.c
	g++ msquic_test.c -o msquic_test -lmsquic -Wl,-rpath=/usr/local/lib
clean:
	rm -rf func_test perf_test msquic_test sample_test
run:
	sh runtest.sh
