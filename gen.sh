#!/bin/sh
# Builds the SARIF file of every hypothesis from a real Trivy scan of this repository.
# Code flows follow the format of https://github.com/aquasecurity/trivy/pull/11556.
set -eu

TRIVY=${TRIVY:-trivy}
cd "$(dirname "$0")"
mkdir -p build

"$TRIVY" config --quiet --skip-dirs build --skip-dirs h9-trivy-fingerprint --format json --output build/report.json .
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
    | ._addr = "\(.ruleId)|\($uri)|\([$occ[].Resource] | join(" > "))"
    | ._code = ($x.CauseMetadata.Code.Lines // [])
  ]
' > build/codeflows.sarif

# hyp DIR FILE FILTER: keeps the results of DIR, applies FILTER and drops _chain.
# A result belongs to DIR by its location or, for a remote module, by the first step of its code flow.
hyp() {
  jq --arg dir "$1" "
    .runs[0].results |= map(select(any(
      .locations[0], .codeFlows[0].threadFlows[0].locations[0].location;
      .physicalLocation.artifactLocation.uri | startswith(\$dir + \"/\")
    )))
    | $3
    | del(.runs[0].results[]._chain, .runs[0].results[]._addr, .runs[0].results[]._code)
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
# Reorder: step 1 keeps the scan order, step 2 reverses it, step 3 drops the module.rds_provisioner[0] instance.
reverse='.runs[0].results |= reverse'
drop0='.runs[0].results |= map(select(.codeFlows[0].threadFlows[0].locations[0].location.message.text | endswith("[0])") | not))'
# Adds the caller chain to the result message, so the alert API shows which instance an alert holds.
via='.runs[0].results[] |= (.message.text += "\nVia: " + ([.codeFlows[0].threadFlows[0].locations[:-1][].location.message.text] | join(" > ")))'
hyp h6-reorder-via step1.sarif "$via"
hyp h6-reorder-via step2.sarif "$via | $reverse"
hyp h6-reorder-via step3.sarif "$via | $reverse | $drop0"
hyp h7-reorder-plain step1.sarif '.'
hyp h7-reorder-plain step2.sarif "$reverse"
hyp h7-reorder-plain step3.sarif "$reverse | $drop0"
# Same steps as h7 with own primaryLocationLineHash from the full instance address, including count/for_each keys.
own='.runs[0].results[] |= (.partialFingerprints.primaryLocationLineHash = ._addr)'
hyp h8-reorder-own-hash step1.sarif "$own"
hyp h8-reorder-own-hash step2.sarif "$own | $reverse"
hyp h8-reorder-own-hash step3.sarif "$own | $reverse | $drop0"
# One result per location with one code flow per module chain; count/for_each instances share a flow.
hyp h5-grouped-flows result.sarif '
  .runs[0].results |= (
    group_by(.ruleId, .locations[0].physicalLocation.artifactLocation.uri, .locations[0].physicalLocation.region.startLine)
    | map((group_by(._chain) | map(.[0])) as $u
      | $u[0] + {codeFlows: [$u[] | .codeFlows[0] + {message: {text: (._chain | split("|")[2])}}]})
  )'
# Primary location in a remote module outside the repository, code flow from the module call.
hyp h10-remote-module result.sarif '.'
# Same as h10 with the code of the cause in region.snippet and the block around it in contextRegion.
# Lines that Trivy truncates in the code of the cause are shown as "...".
hyp h11-remote-snippet result.sarif '
  .runs[0].results[] |= (._code as $c | .locations[0].physicalLocation |= (
    .region.snippet = {text: ([$c[] | select(.IsCause) | .Content] | join("\n"))}
    | .contextRegion = {startLine: $c[0].Number, endLine: $c[-1].Number,
        snippet: {text: ([$c[] | if .Truncated then "  ..." else .Content end] | join("\n"))}}
  ))'
