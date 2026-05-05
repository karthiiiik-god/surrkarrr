# Fix sqlite3.IntegrityError: NOT NULL constraint failed: vulnerabilities.source_tools

## Information Gathered
- The actual SQLite database `vulnerabilities.db` contains a legacy column `source_tools` (NOT NULL, no default) in addition to the current `source_tool` column (NOT NULL, default `'unknown'`).
- The `insert_vulnerability` method in `core/storage/database.py` only inserts into `source_tool`, leaving `source_tools` unpopulated.
- Because `source_tools` has a NOT NULL constraint with no default value, SQLite throws `IntegrityError: NOT NULL constraint failed: vulnerabilities.source_tools`.

## Plan
1. [x] Read relevant files to understand the issue
2. [x] Update `core/storage/database.py` to include the legacy `source_tools` column in the INSERT statement
3. [x] Test by running the Streamlit app and uploading a scan

## Edit Details
- **File:** `core/storage/database.py`
- **Change:** Add `source_tools` to the INSERT column list and bind it to `vuln.source_tool` in the VALUES tuple.

