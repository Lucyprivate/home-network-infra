#!/bin/bash
set -eu
action=${1:?add or remove}
case "$action" in add|remove) :;; *) exit 2;; esac
rule() {
 local permanent
 for permanent in no yes; do
  if cmd --direct --query-rule "$@" >/dev/null; then
   [ "$action" = add ] || cmd --direct --remove-rule "$@"
  else
   [ "$action" = remove ] || cmd --direct --add-rule "$@"
  fi
 done
}
cmd() {
 if [ "$permanent" = yes ]; then firewall-cmd --permanent "$@"; else firewall-cmd "$@"; fi
}
for source in 10.200.0.2/32 10.10.20.0/24; do
 rule ipv4 filter FORWARD 0 -i wg_exit -o eth0 -s "$source" -m conntrack --ctstate NEW,ESTABLISHED,RELATED -m comment --comment vpn-egress-forward -j ACCEPT
 rule ipv4 filter FORWARD 0 -i eth0 -o wg_exit -d "$source" -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment vpn-egress-return -j ACCEPT
 rule ipv4 nat POSTROUTING 0 -o eth0 -s "$source" -m comment --comment vpn-egress-snat -j SNAT --to-source 198.51.100.10
done
