#!/bin/sh
# Builds the SARIF file of every hypothesis from a real Trivy scan of this repository.
# Code flows follow the format of https://github.com/aquasecurity/trivy/pull/11556.
set -eu

TRIVY=${TRIVY:-trivy}
cd "$(dirname "$0")"
mkdir -p build

"$TRIVY" config --quiet --skip-dirs build --format json --output build/report.json .
"$TRIVY" convert --quiet --format sarif --output build/base.sarif build/report.json

# Adds code flows from Occurrences and a temporary _chain field: rule, file and module chain without count/for_each keys.
jq -n --slurpfile r build/report.json --slurpfile s build/base.sarif '
  def strip_key: sub("\\[[^\\]]*\\]$"; "");
  ([$r[0].Results[] | .Misconfigurations[]?]) as $m
  | $s[0]
  | .runs[0].originalUriBaseIds.ROOTPATH.uri = "file:///home/runner/work/sarif-lab/sarif-lab/"
  | .runs[0].results |= [to_entries[] | .key as $i | .value
    | $m[$i] as $x
    | if $x.ID != .ruleId then error("result \($i): \($x.ID) != \(.ruleId)") end
    | .locations[0].physicalLocation as $pl
    | $pl.artifactLocation.uri as $uri
    | ($x.CauseMetadata.Occurrences // [] | reverse) as $occ
    | .codeFlows = [{threadFlows: [{locations:
        ($occ | to_entries | map({nestingLevel: .key, location: {
          physicalLocation: {
            artifactLocation: {uri: .value.Filename, uriBaseId: "ROOTPATH"},
            region: {startLine: .value.Location.StartLine, endLine: .value.Location.EndLine, startColumn: 1, endColumn: 1}
          },
          message: {text: "\(.value.Filename) (\(.value.Resource))"}
        }}))
        + [{nestingLevel: ($occ | length), location: {physicalLocation: $pl, message: {text: $uri}}}]
      }]}]
    | ._chain = "\(.ruleId)|\($uri)|\([$occ[].Resource | strip_key] | join(" > "))"
  ]
' > build/codeflows.sarif

# hyp DIR FILE FILTER: keeps the results of DIR, applies FILTER and drops _chain.
hyp() {
  jq --arg dir "$1" "
    .runs[0].results |= map(select(.locations[0].physicalLocation.artifactLocation.uri | startswith(\$dir + \"/\")))
    | $3
    | del(.runs[0].results[]._chain)
  " build/codeflows.sarif > "$1/$2"
}

# API uploads take the category from automationDetails.
api='.runs[0].automationDetails = {id: ($dir + "/")}'
v1='.runs[0].results[] |= (.partialFingerprints["trivy/finding/v1"] = ._chain)'
v2='.runs[0].results[] |= (.partialFingerprints["trivy/finding/v2"] = "v2|" + ._chain)'

hyp h1-no-fingerprint result.sarif '.'
hyp h1b-no-fingerprint-api result.sarif "$api"
hyp h2-custom-key result.sarif "$v1"
hyp h3-own-linehash result.sarif '.runs[0].results[] |= (.partialFingerprints.primaryLocationLineHash = ._chain)'
hyp h4a-version-overlap step1.sarif "$api | $v1"
hyp h4a-version-overlap step2.sarif "$api | $v1 | $v2"
hyp h4a-version-overlap step3.sarif "$api | $v2"
hyp h4b-version-switch step1.sarif "$api | $v1"
hyp h4b-version-switch step2.sarif "$api | $v2"
# One result per location with one code flow per module chain; count/for_each instances share a flow.
hyp h5-grouped-flows result.sarif '
  .runs[0].results |= (
    group_by(.ruleId, .locations[0].physicalLocation.artifactLocation.uri, .locations[0].physicalLocation.region.startLine)
    | map((group_by(._chain) | map(.[0])) as $u
      | $u[0] + {codeFlows: [$u[] | .codeFlows[0] + {message: {text: (._chain | split("|")[2])}}]})
  )'
