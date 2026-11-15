# MadHacks 2026 - Clearity

Clearity is a FastAPI app that checks car-insurance claim PDFs for hidden text
and suspicious images.

## Run locally

Use **Python 3.12**. The pinned Pillow version may not install cleanly with
newer Python versions.

From the repository root, run:

```bash
cd claimgate/claimgate
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m uvicorn app:app --reload
```

On Windows PowerShell, use `py -3.12` to create the environment and activate it
with `.venv\Scripts\Activate.ps1`:

```powershell
cd claimgate/claimgate
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
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

- If `python3.12` is not found on macOS or Linux, install Python 3.12 and retry.
  On macOS with Homebrew, use `brew install python@3.12`.
- If `pip` reports an “externally-managed-environment” error, make sure the
  virtual environment is activated and install packages with
  `python -m pip install -r requirements.txt`.
- If the app cannot import `fastapi`, `fitz`, or `PIL`, activate the virtual
  environment and rerun the requirements installation command.
