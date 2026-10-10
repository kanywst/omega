#!/usr/bin/env bash
# check-coverage.sh runs the test suite with coverage and fails when the
# total, or any package listed in coverage-floors.txt, drops below its
# floor. The floors are a ratchet: raise them when coverage goes up,
# never lower them to make a change pass.
set -euo pipefail

FLOORS="${FLOORS:-coverage-floors.txt}"
PROFILE="${PROFILE:-coverage.out}"
PKG="${PKG:-./...}"

read -r -a pkgs <<<"$PKG"
out=$(go test -race -count=1 -covermode=atomic -coverprofile="$PROFILE" "${pkgs[@]}")
echo "$out"

fail=0
check() { # name actual floor
	if awk -v a="$2" -v f="$3" 'BEGIN { exit !(a + 0 < f + 0) }'; then
		echo "coverage: $1 is ${2}%, below its floor of ${3}%" >&2
		fail=1
	fi
}

total=$(go tool cover -func="$PROFILE" | awk '/^total:/ { sub("%", "", $NF); print $NF }')
echo "coverage: total ${total}%"

while read -r name floor; do
	case "$name" in "" | \#*) continue ;; esac
	if [[ "$name" == total ]]; then
		check total "$total" "$floor"
		continue
	fi
	actual=$(printf '%s\n' "$out" | awk -v p="$name" '$1 == "ok" && $2 == p { for (i = 1; i <= NF; i++) if ($i == "coverage:") { sub("%", "", $(i + 1)); print $(i + 1) } }')
	if [[ -z "$actual" ]]; then
		echo "coverage: no result for $name (renamed or no tests?)" >&2
		fail=1
		continue
	fi
	check "$name" "$actual" "$floor"
done <"$FLOORS"

exit "$fail"
