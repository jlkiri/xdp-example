ipv6_filter.bpf.o: ipv6_filter.bpf.c
	clang \
	    -target bpf \
		-g \
	    -O2 -o $@ -c $<
