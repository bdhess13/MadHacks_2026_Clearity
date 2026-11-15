# MadHacks 2026 - Clearity

Clearity is a FastAPI app that checks car-insurance claim PDFs for hidden text
and suspicious images.

## Run locally

Use **Python 3.14**. The pinned dependencies include wheels for Python 3.14.

These commands resolve the repository root with Git, so you can paste them
from any folder inside the repo. The environment is created at the repository
root, outside the app directory watched by Uvicorn.

```bash
python3.14 -m venv "$(git rev-parse --show-toplevel)/.venv"
source "$(git rev-parse --show-toplevel)/.venv/bin/activate"
cd "$(git rev-parse --show-toplevel)/claimgate/claimgate"
python --version
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m uvicorn app:app --reload
```

On Windows PowerShell:

```powershell
py -3.14 -m venv "$(git rev-parse --show-toplevel)\.venv"
. "$(git rev-parse --show-toplevel)\.venv\Scripts\Activate.ps1"
Set-Location "$(git rev-parse --show-toplevel)\claimgate\claimgate"
python --version
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m uvicorn app:app --reload
```

Once Uvicorn reports that it is running, open:

- App: <http://127.0.0.1:8000/>
- API docs: <http://127.0.0.1:8000/docs>
- Health check: <http://127.0.0.1:8000/api/health>

Upload a PDF claim in the app to inspect it. Press **Ctrl+C** in the terminal to
stop the server. If port 8000 is already in use, stop the other server or run
`python -m uvicorn app:app --reload --port 8001` and open
<http://127.0.0.1:8001/>.

## Optional Gemini image analysis

Without a Gemini API key, image analysis uses metadata only. To enable Gemini
vision analysis, set `GEMINI_API_KEY` in the same terminal before starting the
server:

```bash
export GEMINI_API_KEY="your-api-key"
```

In PowerShell:

```powershell
$env:GEMINI_API_KEY = "your-api-key"
```

## Troubleshooting

- If `python3.14` is not found on macOS or Linux, install Python 3.14 and retry.
  On macOS with Homebrew, use `brew install python@3.14`.
- If using an existing virtual environment, create a new one with the Python
  version you intend to run. Keep it at the repository root, not inside
  `claimgate/claimgate`. If Uvicorn logs that it detected changes under a
  `.venv` directory, stop the server, activate the repository-root environment,
  install dependencies, and start it again.
- If `pip` reports an “externally-managed-environment” error, make sure the
  virtual environment is activated and install packages with
  `python -m pip install -r requirements.txt`.
- If the app cannot import `fastapi`, `fitz`, or `PIL`, activate the virtual
  environment and rerun the requirements installation command.
