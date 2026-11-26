#!/bin/sh
# Usage: memdiag.sh HELLOVM_BIN N CMD -- runs CMD N times in the background
# under hellovm --root /, then reports RssAnon+RssShmem of every app process.
hv=$1; n=$2; cmd=$3
$hv --root / /bin/sh -c "for i in \$(seq $n); do $cmd & done; sleep 25" 2>/dev/null &
hvpid=$!
sleep 12
desc() { for c in $(ps -e -o pid=,ppid= | awk -v p=$1 '$2==p{print $1}'); do echo $c; desc $c; done; }
pids=$(desc $hvpid)
tot=0; cnt=0; big=0
for p in $pids; do
  a=$(awk '/^RssAnon:/{a=$2}/^RssShmem:/{s=$2}END{print a+s}' /proc/$p/status)
  h=$(awk '/^AnonHugePages:/{print $2}' /proc/$p/smaps_rollup 2>/dev/null)
  tot=$((tot+a)); cnt=$((cnt+1)); [ "$a" -gt "$big" ] && big=$a
done
echo "RESULT $(basename $(dirname $(dirname $(dirname $hv)))) '$cmd' x$n: $cnt app processes, $((tot/1024)) MiB anon+shmem in all, largest ${big} kB, kernel process $(awk '/^RssAnon:/{a=$2}/^RssShmem:/{s=$2}END{print a+s}' /proc/$hvpid/status) kB"
p=$(echo "$pids" | tail -1)
awk '/^[0-9a-f]+-[0-9a-f]+ /{hdr=$0; next} /^Rss:/{rss=$2} /^Anonymous:/{an=$2; if (rss>0) printf "  %-100s Rss=%6d Anon=%6d\n", hdr, rss, an}' /proc/$p/smaps
wait
