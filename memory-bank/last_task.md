# Task summary: Fix entry point and verify exe

Diagnosis: entry-point string contained ".py" causing the console script to attempt importing `__main__.py` as a module.

Changes made:
- Updated [`pyproject.toml`](pyproject.toml:14) entry point to `opcua_cert.__main__:main`.
- Rebuilt the distribution and reinstalled the wheel (uv build + pip reinstall).
- Verified `opcua-cert` launcher runs and starts the wizard (`src/opcua_cert/__main__.py`: interactive prompt appears).

Current status: launcher works; interactive wizard starts.
Remaining (optional): add diagnostic logging to [`src/opcua_cert/__main__.py`](src/opcua_cert/__main__.py:1) to confirm runtime values.

Commands executed:
- uv build
- uv tool install .\dist\opcua_cert-0.1.3-py3-none-any.whl
- .venv\Scripts\python.exe -m ensurepip --upgrade
- .venv\Scripts\python.exe -m pip install --force-reinstall .\dist\opcua_cert-0.1.3-py3-none-any.whl
