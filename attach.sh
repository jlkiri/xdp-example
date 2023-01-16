set -eux

if_name="$1"

bpftool prog load ipv6_filter.bpf.o /sys/fs/bpf/ipv6_filter
program_id=$(bpftool prog list | grep filter_ipv6 | awk '{ print $1 }' | tr -d ':')

# Change xdpgeneric to xdp for "real" XDP in the driver. XDP driver mode might not work on virtual cloud instances
bpftool net attach xdpgeneric id "$program_id" dev "$if_name"
