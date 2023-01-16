set -eux

if_name="$1"

# Change xdpgeneric to xdp for "real" XDP in the driver. XDP driver mode might not work on virtual cloud instances
bpftool net detach xdpgeneric dev "$if_name"
rm -f /sys/fs/bpf/ipv6_filter
