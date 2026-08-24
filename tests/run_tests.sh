#!/bin/sh
set -eu

app=${1:-./build/pam}
test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT HUP INT TERM

echo "[1/5] unanimous agreement"
"$app" sign document/test.pdf "$test_dir/agreement.p7s"
test -s "$test_dir/agreement.p7s"
test -s "$test_dir/agreement.p7s.trust"

echo "[2/5] stored package verification"
"$app" verify "$test_dir/agreement.p7s"

echo "[3/5] refusal prevents agreement output"
set +e
"$app" sign document/test.pdf "$test_dir/refused.p7s" --reject operator-2
status=$?
set -e
test "$status" -eq 2
test ! -e "$test_dir/refused.p7s"
test ! -e "$test_dir/refused.p7s.trust"

echo "[4/5] CMS tampering is rejected"
cp "$test_dir/agreement.p7s" "$test_dir/tampered.p7s"
cp "$test_dir/agreement.p7s.trust" "$test_dir/tampered.p7s.trust"
printf 'X' | dd of="$test_dir/tampered.p7s" bs=1 seek=20 conv=notrunc 2>/dev/null
if "$app" verify "$test_dir/tampered.p7s"; then
    echo "tampered package was unexpectedly accepted" >&2
    exit 1
fi

echo "[5/5] trust-pin tampering is rejected"
cp "$test_dir/agreement.p7s" "$test_dir/bad-trust.p7s"
cp "$test_dir/agreement.p7s.trust" "$test_dir/bad-trust.p7s.trust"
# Change one hexadecimal nibble in operator-1's pinned certificate fingerprint.
sed 's/^operator-1=./operator-1=0/' "$test_dir/bad-trust.p7s.trust" > "$test_dir/trust.tmp"
mv "$test_dir/trust.tmp" "$test_dir/bad-trust.p7s.trust"
if "$app" verify "$test_dir/bad-trust.p7s"; then
    echo "package with a modified trust pin was unexpectedly accepted" >&2
    exit 1
fi

echo "All protocol scenarios passed."
