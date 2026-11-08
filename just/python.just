# Managed by Tailor: just/python.just

[private]
_python $operation $mode="check":
    #!/usr/bin/env bash
    set -euo pipefail
    export UV_PYTHON_DOWNLOADS=never
    unset VIRTUAL_ENV
    for tool in tailor-python uv ruff basedpyright; do
        if ! command -v "${tool}" >/dev/null 2>&1; then
            echo "Error: Python requires ${tool} on PATH" >&2
            exit 1
        fi
    done
    selected_nix_python="$(command -v tailor-python)"
    project_python="${PWD}/.venv/bin/python"
    "${selected_nix_python}" -I - "${PWD}" "${operation}" "${project_python}" <<'TAILOR_PYTHON'
    import json
    import os
    import re
    import subprocess
    import sys
    import tomllib
    from importlib.util import find_spec
    from pathlib import Path

    import packaging
    from packaging.markers import default_environment
    from packaging.requirements import Requirement
    from packaging.specifiers import SpecifierSet
    from packaging.version import Version


    def regular(path, optional=False):
        if optional and not path.exists() and not path.is_symlink():
            return False
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"Python requires a regular {path}, not a symlink")
        return True


    def metadata(data, version, requested=None):
        project = data.get("project", {})
        requirement = project.get("requires-python", "")
        if not requirement:
            raise ValueError("declare project.requires-python")
        spec = SpecifierSet(requirement)
        floors = [s for s in spec if s.operator in (">=", "~=", "==")]
        if not floors or any("*" in s.version for s in floors):
            raise ValueError("requires-python needs an explicit >=, ~= or == Python floor")
        if version not in spec:
            raise ValueError(f"Python {version} does not satisfy {requirement}")
        if requested:
            if not re.fullmatch(r"3\.[0-9]+(?:\.[0-9]+)?", requested):
                raise ValueError(".python-version must contain one Python 3 minor or patch version")
            parts = Version(requested).release
            if version.release[: len(parts)] != parts:
                raise ValueError("selected Python does not match .python-version")
        if not data.get("build-system", {}).get("build-backend") or not project.get("name"):
            raise ValueError("Python requires one root package with a build backend")
        uv = data.get("tool", {}).get("uv", {})
        if "workspace" in uv or uv.get("package") is False:
            raise ValueError("uv workspaces and non-package projects are not supported")
        for source in uv.get("sources", {}).values():
            sources = source if isinstance(source, list) else [source]
            if any(set(item) - {"index", "marker", "extra", "group"} for item in sources):
                raise ValueError("local, URL, VCS and workspace dependency sources are not supported")
        groups = list(project.get("optional-dependencies", {}).values())
        groups += list(data.get("dependency-groups", {}).values())
        groups += [project.get("dependencies", []), uv.get("dev-dependencies", [])]
        for group in groups:
            for item in group:
                if isinstance(item, str) and Requirement(item).url:
                    raise ValueError("direct URL, local and VCS dependencies are not supported")


    def preflight(root, operation, interpreter):
        for directory in (root, *root.parents):
            if directory.is_symlink() or not directory.is_dir():
                raise ValueError(f"unsafe Python project parent {directory}")
        regular(root / "pyproject.toml")
        regular(root / "uv.lock")
        data = tomllib.loads((root / "pyproject.toml").read_text())
        lock = tomllib.loads((root / "uv.lock").read_text())
        for package in lock.get("package", []):
            source = package.get("source", {})
            if source != {"editable": "."} and set(source) != {"registry"}:
                raise ValueError("uv.lock contains an unsupported local, URL, VCS or workspace source")
        requested = None
        if regular(root / ".python-version", optional=True):
            requested = (root / ".python-version").read_text().strip()
        selected = Version(".".join(map(str, sys.version_info[:3])))
        metadata(data, selected, requested)
        for parent in root.parents:
            path = parent / "pyproject.toml"
            if regular(path, optional=True):
                ancestor = tomllib.loads(path.read_text())
                if "workspace" in ancestor.get("tool", {}).get("uv", {}):
                    raise ValueError("uv workspace membership is not supported")
        environment = root / ".venv"
        override = os.environ.get("UV_PROJECT_ENVIRONMENT")
        if override and os.path.abspath(override) != str(environment):
            raise ValueError("unset UV_PROJECT_ENVIRONMENT: Tailor requires the root .venv")
        for directory in (environment, environment / "bin"):
            if directory.is_symlink() or (directory.exists() and not directory.is_dir()):
                raise ValueError(f"unsafe Python environment directory {directory}")
        if operation == "setup":
            regular(environment / "pyvenv.cfg", optional=True)
            return
        regular(environment / "pyvenv.cfg")
        if not Path(interpreter).is_file() or not os.access(interpreter, os.X_OK):
            raise ValueError("run just setup: .venv/bin/python is missing or not executable")
        actual = Version(subprocess.check_output(
            [interpreter, "-I", "-c", "import sys; print('.'.join(map(str, sys.version_info[:3])))"],
            text=True,
        ).strip())
        metadata(data, actual, requested)
        if operation != "lint":
            return
        packaging_path = str(Path(packaging.__path__[0]).parent)
        project_markers = json.loads(subprocess.check_output(
            [interpreter, "-I", "-c", "import sys, json; "
             f"sys.path.insert(0, {packaging_path!r}); "
             "from packaging.markers import default_environment; "
             "print(json.dumps(default_environment()))"], text=True,
        ))
        if project_markers != default_environment():
            raise ValueError("audit requires matching project and Nix Python marker environments")
        if find_spec("pip_audit") is None:
            raise ValueError("the Nix Python must provide pip-audit")
        tool = data.get("tool", {})
        if "basedpyright" not in tool or "ruff" not in tool:
            raise ValueError("declare root BasedPyright and Ruff policies")


    try:
        preflight(Path(sys.argv[1]), sys.argv[2], sys.argv[3])
    except (ValueError, OSError, ImportError, subprocess.CalledProcessError) as error:
        sys.exit(f"Error: {error}")
    TAILOR_PYTHON
    uv lock --check
    if [[ "${operation}" != setup ]]; then
        uv sync --check --locked --python "${project_python}" --no-python-downloads
    fi
    case "${operation}" in
        setup)
            uv sync --locked --python "${selected_nix_python}" --no-python-downloads
            ;;
        build)
            uv build --python "${project_python}" --no-python-downloads
            ;;
        test)
            "${project_python}" -m pytest
            ;;
        lint)
            if [[ "${mode}" == correct ]]; then
                ruff check --fix --no-unsafe-fixes .
                ruff format .
            fi
            ruff format --check .
            ruff check --no-fix .
            basedpyright --pythonpath "${project_python}" --baselinemode=lock
            nixfmt --check nix/python.nix
            requirements="$(mktemp "${TMPDIR:-/tmp}/tailor-python-audit.XXXXXX")"
            trap 'rm -f "${requirements}"' EXIT
            uv export --locked --format requirements-txt --no-emit-project --no-hashes --output-file "${requirements}"
            "${selected_nix_python}" -I -m pip_audit --requirement "${requirements}" --no-deps --disable-pip --strict
            ;;
        *) echo "Error: unknown Python operation" >&2; exit 1 ;;
    esac
