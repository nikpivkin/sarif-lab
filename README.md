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
| h5-grouped-flows | workflow | one result with two code flows | One alert (#19). How the UI shows two flows is not checked yet. |

Not checked yet:

- Which path each of the alerts #7, #8 and #9 shows in the UI.
- How the UI shows the two code flows of alert #19.
