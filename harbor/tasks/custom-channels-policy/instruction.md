The repository in `repo/` uses `proposals` as its source channel and `stable` as its target channel. Its policy is `review-rules.txt`.

Set `PATCHGATE_INBOX=proposals`, `PATCHGATE_MAIN=stable`, and `PATCHGATE_POLICY=review-rules.txt` for each gate command. Set `PATCHGATE_PROTECTED` to an empty value.

Review the benign file, the TODO violation, and the policy update with a scripted model. The model rejects TODO additions only when the active policy specifies rejection. It accepts other changes.

The benign change must enter `stable`. The violation must remain outside it with one model rejection. The custom policy update must need human acceptance without an explicit protection pattern.

Before human acceptance, `stable` must retain its original custom policy. Accept the policy update by hand, then repeat review. Its history must contain gate escalation, then human acceptance.

Both custom channels must contain the approved policy and benign file. The source must retain the rejected notes. The target must exclude them. The default `POLICY.md` must remain unchanged. Neither `main` nor `inbox` may exist.
