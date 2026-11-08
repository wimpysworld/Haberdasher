# Check pinned executable paths without network requests or configuration changes
check-tools:
    @bash just/project/tools.sh

# Run isolated local repository proofs on Linux
proof format="all":
    @bash just/project/proof.sh {{quote(format)}}

# Plan by default, or explicitly publish into an approved destination
[positional-arguments]
publish *args:
    @.venv/bin/python -m haberdasher "$@"
