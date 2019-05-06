#!/usr/bin/env bash

if [ "$1" ];then
    ROUTERS=$1
else
    ROUTERS="1 2 3 4 5 6 7"
fi

echo $ROUTERS;
for rout_num in $ROUTERS
do
  gnome-terminal --window --title="router_0$rout_num" --geometry=100x24+10+10 --command="python3 routing_demon.py "router_0$rout_num""
done