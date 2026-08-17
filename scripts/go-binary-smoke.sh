#!/usr/bin/env bash
# Smoke test for the go-binary class. $1 is the staged-binaries
# directory, $2 the target (<goos>-<goarch>). Every leg runs on native
# hardware, so the binary is simply executed on the machine class it
# ships for.
#
# What it proves, and why these two things: that the shipped bytes RUN
# on their target at all (the property no cross-compiled artifact can
# claim without being executed), and that the binary knows its own
# module version — the stamp `stele version` reads back out of itself,
# which is the same evidence the class asserts at build time and the
# first thing a stranger will check.
set -euo pipefail
dir="$1"
target="$2"

out=$("${dir}/stele" version)
echo "${target}: ${out}"

[[ -n ${out} ]] || {
  echo "stele version printed nothing on ${target}" >&2
  exit 1
}

# A released binary must not report itself as unstamped or as built
# from a modified tree. Go writes "(devel)" when nothing stamped the
# module version and appends "+dirty" when the working tree differed
# from the commit — measured locally, where a build from an edited
# checkout prints v0.0.0-20260817054708-c555d7ef9966+dirty. The class
# already refuses a dirty build at build time; this is the same claim
# read back out of the shipped bytes, on the machine that will run
# them, which is the half a build-time assertion cannot make.
case "${out}" in
  *"(devel)"* | *"+dirty"*)
    echo "stele version reports an unstamped or modified build on ${target}: ${out}" >&2
    exit 1
    ;;
  *) ;;
esac

# The verifier must be able to state its own surface without a network,
# a policy file or a credential — the floor for "a stranger can run it".
"${dir}/stele" help > /dev/null || {
  echo "stele help failed on ${target}" >&2
  exit 1
}
