#!/usr/bin/env bash
#
# Fail when statement coverage falls below a floor.
#
# A floor rather than a target. Coverage here is not a goal in itself —
# the tests exist because the protocol handling, the auth paths and the
# pool lifecycle are where this project's bugs are expensive — but
# coverage does answer one question a review cannot: whether the code
# somebody just added is exercised by anything. Without a gate that
# answer drifts downwards one hurried pull request at a time.
#
# Deliberately a single number for the whole module instead of a
# per-package matrix: a per-package floor invites writing tests for the
# package that is easiest to move rather than the code that most needs
# them.
#
# Usage: scripts/coverage-gate.sh <profile> <floor-percent>
set -euo pipefail

profile=${1:?usage: coverage-gate.sh <profile> <floor-percent>}
floor=${2:?usage: coverage-gate.sh <profile> <floor-percent>}

if [ ! -s "$profile" ]; then
	echo "coverage-gate: $profile is missing or empty — did the test run fail?" >&2
	exit 1
fi

total=$(go tool cover -func="$profile" | awk '/^total:/ { gsub("%", "", $NF); print $NF }')
if [ -z "$total" ]; then
	echo "coverage-gate: could not read a total out of $profile" >&2
	exit 1
fi

echo "statement coverage: ${total}% (floor ${floor}%)"

# awk rather than bash arithmetic: these are decimals, and [ ] would
# compare them as strings — "9.5" would pass a floor of "90".
if awk -v total="$total" -v floor="$floor" 'BEGIN { exit !(total < floor) }'; then
	cat >&2 <<EOF
coverage-gate: coverage ${total}% is below the floor of ${floor}%.

Either cover the new code, or — if a branch genuinely cannot be reached
from a test — say so in a comment where it lives and lower the floor in
the same commit, so the decision is reviewable rather than implicit.
EOF
	exit 1
fi
