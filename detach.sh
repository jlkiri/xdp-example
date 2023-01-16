set -eux

if_name="$1"

bpftool net detach xdpgeneric dev "$if_name"
rm -f /sys/fs/bpf/ipv6_filter
