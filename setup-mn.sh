#!/bin/bash
DEPTH="${1:-3}"

echo "Depth is $DEPTH"

sudo mn --controller=remote,127.0.0.1:6653 \
--topo=tree,depth=$DEPTH,fanout=3 \
--switch=ovs,protocols=OpenFlow14