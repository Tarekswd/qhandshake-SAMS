#!/usr/bin/env bash
# Runs the ProVerif model and a signature-removed mutant; fails unless every result matches expectations.
# Usage: PROVERIF=/path/to/proverif bash formal/run.sh
set -uo pipefail
PV="${PROVERIF:-proverif}"
cd "$(dirname "$0")"
check() { # file, expected RESULT lines (one per line)
  local out; out=$("$PV" "$1" 2>&1 | grep '^RESULT' | sed -E 's/_[0-9]+//g')  # ProVerif renames variables (ch_3)
  echo "$out"
  local ok=0
  while IFS= read -r exp; do
    [ -z "$exp" ] && continue
    if ! grep -qF -- "$exp" <<< "$out"; then echo "MISSING EXPECTED: $exp"; ok=1; fi
  done <<< "$2"
  return $ok
}
echo "== model"
check qhandshake.pv "not attacker(secretHyb[]) is true.
not attacker(secretClassic[]) is false.
event(ClientAccept(ch,grp,k)) ==> event(ServerChose(ch,grp)) is true.
inj-event(ClientAccept(ch,grp,k)) ==> inj-event(ServerChose(ch,grp)) is true.
not event(ClientAccept(ch,HYB,k)) is false."
m=$?
echo "== mutant: client does not verify the server signature"
sed 's/(\*SIGCHECK\*) if checksign(sv, pkS) = H((ch, sh)) then//' qhandshake.pv > /tmp/qh_nosig.pv
check /tmp/qh_nosig.pv "event(ClientAccept(ch,grp,k)) ==> event(ServerChose(ch,grp)) is false."
n=$?
[ $m -eq 0 ] && [ $n -eq 0 ] && echo "ALL EXPECTED RESULTS OBTAINED" && exit 0
echo "UNEXPECTED RESULTS"; exit 1
