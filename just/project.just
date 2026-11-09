# Check pinned executable paths without network requests or configuration changes
check-tools:
    @bash just/project/tools.sh

# Run isolated local repository proofs on Linux
proof format="all":
    @bash just/project/proof.sh {{quote(format)}}

# Show a read-only plan for haberdasher.yaml without storage changes or signing
plan:
    @.venv/bin/python -m haberdasher plan

# Publish every format in haberdasher.yaml to its R2 bucket
publish:
    @.venv/bin/python -m haberdasher publish

# Delete stale haberdasher.lock objects from the R2 buckets after a stopped run
unlock:
    @.venv/bin/python -m haberdasher unlock
