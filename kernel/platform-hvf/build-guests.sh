#!/bin/sh
# Builds the guests the HVF platform's tests need beyond the assembly ones
# (which test-guest/build.rs builds on the Mac), as aarch64 Linux
# programs, in the Linux dev container, and assembles them into one image
# directory:
#
#   kernel/platform-hvf/build-guests.sh [IMAGE]
#
# run from the repository root on an Apple silicon Mac with Docker (the
# container is arm64, so no cross compiler is needed). IMAGE is the dev
# image (default hellovm-dev, built from kernel/dev/Dockerfile). Writes
# kernel/target/hvf-guests/root:
#
#   guests/smoke, pie, signals, threads, forks
#                        kernel/test-guest/c, built by the container's gcc
#                        and glibc with the flags of test-guest/build.rs
#                        (static-PIE), except smoke (static, as before)
#   guests/dynamic       kernel/test-guest/c/dynamic.c, linked dynamically
#   bin/busybox          the container's /bin/busybox (Debian
#                        busybox-static), with applet links in bin/
#   usr/bin/python3      the container's CPython (Debian python3), with
#                        its standard library (/usr/lib/python3.X, without
#                        its test suite) and extension modules
#   lib/..., usr/lib/... the shared libraries and the program interpreter
#                        the dynamic programs need, from ldd, at the same
#                        paths as in the container
#   greeting.txt         a file smoke reads
#   MANIFEST             the image, compiler and package versions used
#
# Then run the tests with
#
#   HELLOVM_HVF_GUESTS=$PWD/kernel/target/hvf-guests/root cargo test -p hellovm-platform-hvf
set -eu
image=${1:-hellovm-dev}
out=kernel/target/hvf-guests
rm -rf "$out/root"
mkdir -p "$out/root"
docker run --rm --init --platform linux/arm64 -v "$PWD":/src -w /src "$image" sh -eu -c '
root=kernel/target/hvf-guests/root
c=kernel/test-guest/c
mkdir -p "$root/guests" "$root/bin" "$root/usr/bin" "$root/tmp" "$root/root" "$root/etc"
gcc -static -O2 -Wl,--build-id=none -o "$root/guests/smoke" "$c/smoke.c"
for guest in pie signals threads forks; do
    gcc -static-pie -fPIE -O2 -pthread -Wl,--build-id=none -o "$root/guests/$guest" "$c/$guest.c"
done
gcc -O2 -Wl,--build-id=none -o "$root/guests/dynamic" "$c/dynamic.c" -lm

# Copies a file of the container to the same path in the image,
# following symlinks.
copy() {
    mkdir -p "$root$(dirname "$1")"
    cp -L "$1" "$root$1"
}
# A dynamic program and the libraries ldd finds for it.
with_libs() {
    for lib in $(ldd "$1" 2>/dev/null | tr -s " \t" "\n\n" | grep "^/" || true); do
        [ -e "$root$lib" ] || copy "$lib"
    done
}

cp /bin/busybox "$root/bin/busybox"
for applet in sh ash echo cat tr wc sort uniq head tail seq grep sed ls sleep true false \
    kill ps env yes cut tee expr printf test mkdir rm; do
    ln -sf busybox "$root/bin/$applet"
done

python=$(readlink -f /usr/bin/python3)
version=$(basename "$python")
copy "$python"
ln -sf "$version" "$root/usr/bin/python3"
mkdir -p "$root/usr/lib"
# The standard library without its own tests, idle and tkinter.
tar -C /usr/lib --exclude="$version/test" --exclude="$version/idlelib" \
    --exclude="$version/tkinter" --exclude="__pycache__" -cf - "$version" |
    tar -C "$root/usr/lib" -xf -
with_libs "$python"
for module in "/usr/lib/$version/lib-dynload/"*.so; do
    with_libs "$module"
done
with_libs "$root/guests/dynamic"
echo "root:x:0:0:root:/root:/bin/sh" > "$root/etc/passwd"
echo "hello from a file" > "$root/greeting.txt"

{
    echo "built in $(cat /etc/debian_version 2>/dev/null | sed "s/^/Debian /") ($(uname -m))"
    gcc --version | head -1
    dpkg-query -W -f="\${Package} \${Version}\n" libc6 busybox-static python3 "$version" \
        "lib$version-stdlib" 2>/dev/null || true
} > "$root/MANIFEST"
'
echo "image: $(docker image inspect --format '{{.Id}}' "$image")" >> "$out/root/MANIFEST"
cat "$out/root/MANIFEST"
du -sh "$out/root"
