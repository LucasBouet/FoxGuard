# Golden baseline

`full_ruleset.nft` is an approval-test baseline: the exact nft script produced
by a realistic configuration.

It is created automatically on the first `pytest` run (the test skips with a
message that it wrote the file), then **commit it**. From then on, any change to
the generator's output shows up as a reviewable diff instead of silently
altering what gets pushed to your gateway.

To accept an intentional change:

```sh
make golden          # or: FOXGUARD_UPDATE_GOLDEN=1 pytest -k golden
git diff             # read every line before committing
```

If you have `nft` available, it is worth checking the baseline really parses:

```sh
nft -c -f backend/tests/golden/full_ruleset.nft
```
