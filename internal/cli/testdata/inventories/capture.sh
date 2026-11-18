#!/usr/bin/env bash
# Capture one golden set for TestDeriveInventoriesGolden from a
# release-lab publish run (stele#396): the plan artifacts inside their
# one-day retention, the shipped inventories, the inputs the run used,
# the assert policy at its canon pin (plus the canon's inventory
# declarations, canon-inventory.json), and cargo metadata for every
# closure selection the plans name. One command:
#
#   internal/cli/testdata/inventories/capture.sh <publish run id>
#
# Needs gh (signed in), git, jq and cargo. Writes
# release-lab-<version>-run-<id>/ beside this script.
set -euo pipefail

run=${1:?usage: capture.sh <publish run id>}
repo=monumental-archive/release-lab
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
rc=0
trap 'rc=$?; rm -rf "${work}"; [ -n "${org_done:-}" ] || [ "${rc}" -ne 0 ] || rc=1; exit "${rc}"' EXIT

meta=$(gh run view "${run}" -R "${repo}" --json headSha,headBranch,url)
sha=$(jq -r .headSha <<< "${meta}")
tag=$(jq -r .headBranch <<< "${meta}")
url=$(jq -r .url <<< "${meta}")
[[ ${tag} =~ ^v[0-9] ]] || {
  echo "capture: run ${run} ran on ${tag}, not a release tag" >&2
  exit 1
}
version=${tag#v}
set_dir="${here}/release-lab-${version}-run-${run}"
mkdir -p "${set_dir}/plans" "${set_dir}/shipped" "${set_dir}/cargo"

# The plans, as the publish job downloaded them.
gh run download "${run}" -R "${repo}" -p 'sbom-plan-*' -D "${set_dir}/plans"
for f in "${set_dir}"/plans/*/plan.json; do
  mv "${f}" "${f}.golden"
done

# The shipped per-artifact inventories and the release view, kept
# byte for byte.
gh release download "${tag}" -R "${repo}" -p 'sbom-*.spdx.json' \
  -p "release-lab-${version}.spdx.json" -D "${work}/shipped"
for f in "${work}"/shipped/*.spdx.json; do
  mv "${f}" "${set_dir}/shipped/$(basename "${f}").golden"
done

# What the run was given: the caller's ran classes and majors, and the
# evidence manifest's declared classes and machinery version.
wf=$(gh api "repos/${repo}/contents/.github/workflows/publish.yml?ref=${sha}" --jq .content | base64 -d)
classes=$(sed -n 's/^ *classes: *//p' <<< "${wf}" | head -1)
majors=$(sed -n 's/^ *pg-majors: *//p' <<< "${wf}" | head -1)
canon=$(sed -n 's#.*/publish.yml@\([0-9a-f]\{40\}\).*#\1#p' <<< "${wf}" | head -1)
manifest=$(gh release download "${tag}" -R "${repo}" -p evidence-manifest.json -O -)
evidence=$(jq -r '.classes | join(",")' <<< "${manifest}")
machinery=$(jq -r .machineryVersion <<< "${manifest}")
created=$(gh api "repos/${repo}/commits/${sha}" --jq .commit.committer.date)

jq -n --arg repo "${repo}" --arg version "${version}" --arg created "${created}" \
  --arg classes "${classes}" --arg evidence "${evidence}" --arg machinery "${machinery}" \
  --arg variants "${majors}" --arg run "${url}" \
  '{repo: $repo, version: $version, created: $created, name: "release-lab", classes: $classes,
    evidenceClasses: $evidence, machineryVersion: $machinery, variants: $variants, run: $run}' \
  > "${set_dir}/inputs.json"

# The assert policy at the run's canon pin, on the epoch this stele
# reads, with the canon's inventory declarations.
gh api "repos/monumental-archive/.github/contents/slsa/assert-policy.json?ref=${canon}" --jq .content \
  | base64 -d \
  | jq --slurpfile inv "${here}/canon-inventory.json" \
    '.schema = 9 | .evidence.classes |= with_entries(
       if $inv[0][.key] then .value.inventory = $inv[0][.key] else . end)' \
    > "${set_dir}/assert-policy.json"

# Cargo metadata for every distinct closure selection, resolved in the
# released tree exactly as stele's resolver asks for it.
# A cargo that is not a version manager's shim: a shim reads the
# clone's own config, which this script does not trust. CARGO_BIN
# overrides; otherwise rustup's own proxy.
cargo_bin=${CARGO_BIN:-${CARGO_HOME:-${HOME}/.cargo}/bin/cargo}
[[ -x ${cargo_bin} ]] || {
  echo "capture: no cargo at ${cargo_bin}; set CARGO_BIN" >&2
  exit 1
}
git clone -q --filter=blob:none "https://github.com/${repo}.git" "${work}/tree"
git -C "${work}/tree" checkout -q "${sha}"
selections=$(jq -rs '[.[][] | .params | [
    (if (.features // []) | length > 0 then "--features " + ((.features) | join(",")) else empty end),
    (if .noDefaultFeatures then "--no-default-features" else empty end)
  ] | join(" ")] | unique | .[]' "${set_dir}"/plans/*/plan.json.golden)
index="[]"
n=0
while IFS= read -r flags; do
  n=$((n + 1))
  file="selection-${n}.json.golden"
  # shellcheck disable=SC2086 # the flags are cargo's own words, split on purpose
  (cd "${work}/tree" && "${cargo_bin}" metadata --format-version 1 --locked ${flags}) > "${set_dir}/cargo/${file}"
  index=$(jq --arg flags "${flags}" --arg file "${file}" '. + [{flags: $flags, file: $file}]' <<< "${index}")
done <<< "${selections}"
jq . <<< "${index}" > "${set_dir}/cargo/index.json"
# The two files built here, not recorded, take the org's JSON layout.
jq . "${set_dir}/assert-policy.json" > "${work}/policy.json"
mv "${work}/policy.json" "${set_dir}/assert-policy.json"

echo "capture: ${set_dir#"${here}"/} from ${url}"
org_done=1
