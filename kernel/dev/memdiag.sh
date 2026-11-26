#!/bin/sh
# Usage: diag.sh HELLOVM_BIN [ENV...] -- runs 10 sleeps under hellovm --root / and dumps memory of app processes.
hv=$1; shift
echo "== kernel $(uname -rm)"; cat /sys/kernel/mm/transparent_hugepage/enabled /sys/kernel/mm/transparent_hugepage/defrag 2>&1
ls -la /usr/lib/locale/ 2>&1; head -1 /etc/os-release; ls -laL /bin/sh /bin/sleep
env | grep -E '^(LANG|LC_)'
env "$@" $hv --root / /bin/sh -c 'for i in 1 2 3 4 5 6 7 8 9 10; do sleep 20 & done; sleep 20' 2>/dev/null &
hvpid=$!
sleep 6
kpid=$(pgrep -P $hvpid -x hellovm || echo $hvpid)
all=$(ps -e -o pid=,ppid=,comm= )
desc() { for c in $(ps -e -o pid=,ppid= | awk -v p=$1 '$2==p{print $1}'); do echo $c; desc $c; done; }
pids=$(desc $hvpid)
tot=0
for p in $pids; do
  a=$(awk '/^RssAnon:/{a=$2}/^RssShmem:/{s=$2}END{print a+s}' /proc/$p/status)
  h=$(awk '/^AnonHugePages:/{print $2}' /proc/$p/smaps_rollup 2>/dev/null)
  echo "pid $p comm=$(cat /proc/$p/comm) anon+shmem=${a}kB AnonHugePages=${h}kB"
done
p=$(echo "$pids" | tail -1)
echo "== smaps of $p (mappings with Rss>0)"
awk '/^[0-9a-f]+-[0-9a-f]+ /{hdr=$0; next} /^Rss:/{rss=$2} /^AnonHugePages:/{ah=$2; if (rss>0) printf "%-80s Rss=%6d AnonHuge=%6d\n", hdr, rss, ah}' /proc/$p/smaps
wait
