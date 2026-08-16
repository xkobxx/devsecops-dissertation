# Benchmark labelling and evaluation partitions

Trust Gate uses a two-reviewer benchmark workflow with explicit disagreement
adjudication, uncertainty, agreement metrics, blind evaluation partitions, and
rule-tuning leakage controls. The workflow records evidence; it does not infer
that a human review occurred merely because fixture classifications exist.

The versioned rules are in `benchmarks/labelling/rules-v1.json`. The partition
contract is `benchmarks/partitions/multilingual-v1.json`.

## Partition model

The multilingual benchmark has three disjoint partitions:

- `development_public` contains the 27 Phase 17.1 cases. Only this partition may
  be used to author or tune scanner rules.
- `evaluation_public_blind` contains public fixture content with labels withheld
  behind salted SHA-256 commitments. Evaluators freeze results before a
  custodian reveals a label and salt.
- `evaluation_private` publishes only fixture and label commitments. Private
  content, labels, and salts must remain with the benchmark custodian outside
  the public repository.

Validate paths, hashes, commitments, disjoint identifiers, and the tuning
policy:

```bash
trustgate benchmark --partition-check
```

The validator rejects byte-identical development/blind fixtures, overlapping
case IDs, paths outside `benchmarks/blind`, local paths in private commitment
records, empty partitions, and any policy that permits blind or private data in
rule tuning. `benchmarks/private/` and `benchmarks/labels/private/` are ignored
as a defensive backstop; custodians should normally store private data outside
the checkout entirely.

Verify the committed rule-tuning declaration:

```bash
trustgate benchmark \
  --tuning-check \
  --tuning-config benchmarks/configurations/rule-tuning-v1.json \
  --output reports/benchmark-tuning-control.json
```

The resulting receipt binds the configuration to the partition digest. A
configuration fails if it trains on `evaluation_public_blind` or
`evaluation_private`, or fails to explicitly exclude either partition.

## Independent review

Generate separate label-empty drafts for two real reviewers:

```bash
trustgate benchmark \
  --review-template \
  --reviewer-id reviewer-alpha \
  --output review-alpha.draft.json

trustgate benchmark \
  --review-template \
  --reviewer-id reviewer-beta \
  --output review-beta.draft.json
```

Reviewers must work independently and must not inspect the other draft or
scanner output. For every development-public case, each reviewer records:

- `vulnerable`, `patched`, or `safe_lookalike`;
- `certain`, `probable`, or `uncertain` confidence;
- at least one fixture path, current SHA-256, and line range; and
- a case-specific rationale.

Each reviewer also supplies a distinct identifier, conflict disclosure,
timezone-bearing completion timestamp, and explicit independence attestation.
The rules forbid treating scanner agreement as ground truth.

After completing a draft, remove the `-DRAFT` suffix from its review ID, set the
attestation, disclosure, and timestamp, and seal it:

```bash
trustgate benchmark \
  --seal-review \
  --review review-alpha.draft.json \
  --output review-alpha.json
```

Sealing produces a canonical digest. Any later edit invalidates the record.
The final evaluator also verifies that every evidence path belongs to the case
and that its hash matches the corpus.

## Disagreement and adjudication

Evaluate both sealed reviews:

```bash
trustgate benchmark \
  --labelling-check \
  --review review-alpha.json \
  --review review-beta.json \
  --output reports/benchmark-labelling.json
```

Trust Gate calculates raw agreement and Cohen's kappa across all three
classifications. If reviewers disagree, the command fails and lists every case
requiring adjudication. A third person—distinct from both reviewers—creates one
record per disagreement with:

- both review digests;
- the final classification and uncertainty;
- an evidence-based rationale; and
- a timezone-bearing adjudication timestamp.

Seal each record with `--seal-adjudication --adjudication DRAFT --output SEALED`
and repeat `--adjudication SEALED` on the labelling-check command. Missing,
extra, duplicate, tampered, or reviewer-authored adjudications fail closed.

The final receipt preserves both original reviewer decisions, their evidence,
rationales and confidence, the adjudication digest where applicable, raw
agreement, Cohen's kappa, all input digests, and a deterministic labelling
digest. Agreed labels inherit the more cautious reviewer confidence;
adjudicated labels retain adjudicator uncertainty.

## Blind label commitments

Custodians create a commitment over the blind ID, classification, and at least
16 characters of cryptographically random salt using
`create_label_commitment`. The salt and classification remain outside the
public repository until results are frozen. `verify_label_commitment` checks the
reveal using constant-time digest comparison. Reusing a salt or committing it
beside the fixture defeats the blind boundary.

Public fixture content may reveal security-relevant patterns to a human reader;
the blind property is that expected labels and evaluation outcomes are withheld
from scanner authors and rule tuning. Private content is additionally withheld.

## Current evidence status

The contracts, partitions, blind fixtures, metrics, adjudication workflow, and
leakage controls are implemented and tested. The repository intentionally does
not contain fabricated human review records. Until two genuine independent
reviews cover every development-public case:

- multilingual corpus classifications remain unreviewed assertions;
- no multilingual precision or recall claim may be published;
- the historical Flask-only metrics remain the only published metrics; and
- the Phase 17.2 human-review acceptance items remain incomplete.
