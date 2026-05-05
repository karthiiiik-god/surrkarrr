# SurrKarr Deployment Notes

## Local Run

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

## Docker Run

```powershell
docker build -t surrkarr .
docker run --rm -p 8501:8501 surrkarr
```

## Notes

- File-upload workflows work without local scanner binaries.
- Live scans require the relevant scanner tools, such as `nmap`, `nikto`, or `nuclei`, to be installed on the host/container.
- Live scan artifacts are stored under `scan_artifacts/` and each operation is recorded in the `scan_jobs` table.
- The current app is suitable for an internal MVP or lab deployment. For internet-facing production use, add stronger authentication, secret management, TLS termination, and centralized logging.
