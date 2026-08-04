# Secret protection

This pack blocks a secret that has been safely validated, investigates unknown
validation state, and requires serious new secret findings to be fixed before
release. Validation must never expose, replay, or log secret material.

The included test exercises the validated-secret rule. Add rotation, revocation,
incident response, and redaction procedures outside this policy.

Automated evidence does not guarantee compliance or complete secret protection.
Use of this policy does not change that limitation. Provider-side revocation
checks and qualified human incident review remain necessary.
