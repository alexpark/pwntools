#!/bin/sh
#strace -ifx ./demo64 -
socat TCP-LISTEN:31337,reuseaddr,fork exec:"strace -ifx ./demo64 -"
