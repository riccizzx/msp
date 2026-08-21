#!/bin/sh
set -eu

app=${1:-./build/pam}
test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT HUP INT TERM

echo "[1/4] unanimous agreement"
"$app" sign document/test.pdf "$test_dir/agreement.p7s"
test -s "$test_dir/agreement.p7s"

echo "[2/4] stored package verification"
"$app" verify "$test_dir/agreement.p7s"

echo "[3/4] refusal prevents agreement output"
set +e
"$app" sign document/test.pdf "$test_dir/refused.p7s" --reject operator-2
status=$?
set -e
test "$status" -eq 2
test ! -e "$test_dir/refused.p7s"

echo "[4/4] tampering is rejected"
cp "$test_dir/agreement.p7s" "$test_dir/tampered.p7s"
printf 'X' | dd of="$test_dir/tampered.p7s" bs=1 seek=20 conv=notrunc 2>/dev/null
if "$app" verify "$test_dir/tampered.p7s"; then
    echo "tampered package was unexpectedly accepted" >&2
    exit 1
fi

echo "All challenge scenarios passed."
