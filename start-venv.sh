#!/usr/bin/env bash
# Activate domainfinder's virtual environment, creating it on first use.
#
# Usage:  source start-venv.sh        (or:  . start-venv.sh)

# Run as ./start-venv.sh, the venv would activate in a child shell that exits
# straight away, so the script insists on being sourced.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Run this with 'source' so the venv stays active in your shell:" >&2
    echo "    source ${0}" >&2
    exit 1
fi

_df_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! -f "$_df_dir/.venv/bin/activate" ]]; then
    echo "No .venv yet: creating it and installing domainfinder..."
    if ! python3 -m venv "$_df_dir/.venv"; then
        echo "Could not create the venv (on Ubuntu: sudo apt install python3-venv)." >&2
        unset _df_dir
        return 1
    fi
    PIP_DISABLE_PIP_VERSION_CHECK=1 "$_df_dir/.venv/bin/pip" install -q -e "$_df_dir[dev]" || { unset _df_dir; return 1; }
fi

source "$_df_dir/.venv/bin/activate"
echo "domainfinder venv active ($(python --version 2>&1)). Type 'deactivate' to leave it."
unset _df_dir
