# sarif-lab

Experiments with Trivy SARIF output in GitHub code scanning. They check how code scanning turns results with code flows and `partialFingerprints` into alerts. The context is [aquasecurity/trivy#11556](https://github.com/aquasecurity/trivy/pull/11556) and [aquasecurity/trivy#9076](https://github.com/aquasecurity/trivy/issues/9076).

## Layout

Each `h*` directory holds a copy of the same Terraform fixture and the SARIF files of one hypothesis. The module `modules/sg` has an egress rule to `0.0.0.0/0` (AWS-0104). `service/main.tf` calls it with `count = 2`, and `other/main.tf` calls it once, so Trivy reports three findings on the same line of the module.

`gen.sh` scans the repository with Trivy 0.74.0, adds code flows in the format of #11556 and builds the SARIF file of every hypothesis with `jq`. Each hypothesis has its own category, and its alerts point to its own directory.

## How to upload

Through `upload-sarif`, which computes `primaryLocationLineHash` from the file contents:

```sh
gh workflow run upload.yaml -R nikpivkin/sarif-lab -f sarif=h1-no-fingerprint/result.sarif -f category=h1-no-fingerprint
```

Through the API, which stores the SARIF as is. The category comes from `automationDetails.id` in the file:

```sh
gh api -X POST repos/nikpivkin/sarif-lab/code-scanning/sarifs -f commit_sha=$(git rev-parse HEAD) -f ref=refs/heads/main -f sarif="$(gzip -c h4a-version-overlap/step1.sarif | base64)"
```

Steps of one hypothesis go to different commits, so each step is a new analysis.

To see the stored fingerprints of an analysis:

```sh
gh api -H 'Accept: application/sarif+json' repos/nikpivkin/sarif-lab/code-scanning/analyses/<id> --jq '.runs[0].results[].partialFingerprints'
```

## Results

| Hypothesis | Upload | SARIF | Result |
| --- | --- | --- | --- |
| h1-no-fingerprint | workflow | three results on one line, no fingerprints | The action gives all three the same `primaryLocationLineHash`. Code scanning still opens three alerts (#7, #8, #9), and a second upload on a new commit keeps them. |
| h1b-no-fingerprint-api | API | same as h1 | Three alerts (#4, #5, #6). The stored `primaryLocationLineHash` is empty. |
| h2-custom-key | workflow | `trivy/finding/v1` with the module chain without keys | The stored SARIF has only `primaryLocationLineHash` from the action, the custom key is dropped. Three alerts (#1, #2, #3), although `[0]` and `[1]` share the key value. |
| h3-own-linehash | workflow | own value in `primaryLocationLineHash` | The action keeps the value. Three alerts (#13, #14, #15), although two results share the value. |
| h4a-version-overlap | API | step 1 `v1`, step 2 `v1` and `v2`, step 3 `v2` | Alerts #10, #11, #12 stay open through all steps. |
| h4b-version-switch | API | step 1 `v1`, step 2 `v2` | Alerts #16, #17, #18 stay open, so custom keys do not take part in matching. |
| h5-grouped-flows | workflow | one result with two code flows | One alert (#19). "Show paths" says "2 paths available" and lets you switch between them, but both entries are named "3 steps in main.tf" because the UI does not show the code flow message. |

| h6-reorder-via | workflow | step 1 scan order, step 2 reversed, step 3 without `module.rds_provisioner[0]`; the message has a `Via:` line | See below. |
| h7-reorder-plain | workflow | same steps as h6 with plain messages | Same states as h6: #24 (dismissed for `[0]`) stays dismissed, #25 is fixed after step 3. |

## Reorder (h6)

Results with the same fingerprint are matched by their position in the SARIF, and the message is ignored. The alert for `[0]` (#21) was dismissed as "won't fix" after step 1.

| Alert | Step 1 | Step 2 | Step 3 |
| --- | --- | --- | --- |
| #20 | `rds_api`, open | `[1]`, open | `[1]`, open |
| #21 | `[0]`, dismissed | `[0]`, dismissed | `rds_api`, dismissed |
| #22 | `[1]`, open | `rds_api`, open | fixed |

After `[0]` is gone, the dismissal moves to the `rds_api` finding, and the alert that is marked as fixed is a different one.

## UI

- The alert page and the alert list look the same for #7, #8 and #9. Only "Show paths" tells them apart, and each alert shows the path of its own instance, for example #9 starts at `service/main.tf (module.rds_provisioner[1])`.
- The step title is the message of the thread flow location. The first step is marked "Source" and the last one "Sink".
- A region with `endColumn: 1` ends at the start of its last line, so the closing `}` of a block is not highlighted.
