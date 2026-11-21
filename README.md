# CryptoBench
 
Timing benchmarks for classical and post-quantum cryptographic algorithms (key establishment, digital signatures and authenticated encryption), using Python's `pyca/cryptography` package.
 
## Files
 
| File | Purpose |
|---|---|
| `my_project.py` | The benchmark. Produces `raw.csv` (one row per timed run). |
| `analyse.py` | The analysis. Reads `raw.csv` and makes the 3 tables and 3 plots. |
| `requirements.txt` | Python packages needed. |
| `results/run-1/raw.csv` | Output from the usual machine. |
| `results/run-2/raw.csv` | Output from the second environment. |
 
## Step 1: Set up a virtual environment (once per machine)
 
Install with `pip` inside a virtual environment, **not** with the operating system's package manager. Python 3.9 or newer is needed.
 
Linux:
 
```bash
python3 -m venv venv
source venv/bin/activate
```
 
Windows (PowerShell):
 
```powershell
python -m venv venv
venv\Scripts\Activate.ps1
```
 
The prompt should now start with `(venv)`. Then install the packages:
 
```bash
python -m pip install -r requirements.txt
```
 
`requirements.txt` contains:
 
```
cryptography>=50
matplotlib
```
 
`matplotlib` is only needed for `analyse.py` (the plots). `my_project.py` needs nothing except `cryptography` and the standard library.
 
Check the version is 50 or higher:
 
```bash
python -c "import cryptography; print(cryptography.__version__)"
```
 
## Step 2: Quick test run (do this first)
 
The full run takes a long time (RSA-7680 key generation is slow). Check that the script works before committing to it:
 
1. In `my_project.py`, temporarily change:
   - `RUNS = 101` to `RUNS = 5`
   - `RSA_KEYGEN_RUNS = 21` to `RSA_KEYGEN_RUNS = 2`
2. Run:
```bash
python my_project.py results/test
```
3. Open `results/test/raw.csv` and check that:
   - the first line is exactly `part,algorithm,operation,message_bytes,run,nanoseconds`
   - there are `kem`, `signature` and `aead` rows
   - algorithm names are spelt exactly as in Tables 1 to 3 of the brief
   - `aead` rows have `message_bytes` of 64, 1024, 16384 and 1048576
4. Change `RUNS` back to 101 and `RSA_KEYGEN_RUNS` back to 21, and **delete `results/test`** so it does not end up in the repository.
If you get an `ImportError` for `mldsa` or `mlkem`, the module path differs in your version of `cryptography`; check the v50 documentation.
 
## Step 3: Full run on your usual machine
 
Close every other program (browser, chat apps, etc.), plug in mains power, and do not touch the computer while it runs. The script is single-threaded, so just leave it alone.
 
```bash
python my_project.py results/run-1
```
 
This writes `results/run-1/raw.csv`. Expect it to take a while.
 
## Step 4: Full run in the second environment
 
Run the **same script, unchanged**, in a second environment: a virtual machine, a laptop on battery, a Raspberry Pi, a lab machine, etc.
 
- Install the same Python version and the same `cryptography` version (for example `pip install "cryptography==<exact version from run 1>"`).
- Write down what the environment is. For a VM: the hypervisor (e.g. VirtualBox), the number of cores, and the memory you gave it.
- Run:
```bash
python my_project.py results/run-2
```
 
Copy `results/run-2/raw.csv` back into the repository.
 
## Step 5: Details for Report Part 1
 
Do this on **both** machines. You need the CPU model and architecture, number of cores, memory, operating system, and the versions of Python, `cryptography` and OpenSSL.
 
```bash
python --version
python -c "import cryptography; print(cryptography.__version__)"
python -c "from cryptography.hazmat.backends.openssl.backend import backend; print(backend.openssl_version_text())"
```
 
If the last command fails, look in the `cryptography` docs for how to print the OpenSSL version it is built against.
 
CPU, cores and memory:
 
- Linux: `lscpu` and `free -h`
- Windows: Task Manager > Performance, or `systeminfo`
## Step 6: Make the tables and plots
 
```bash
python analyse.py results/run-1 "Usual machine"
python analyse.py results/run-2 "Second environment"
```
 
The second argument is the label used in the plot titles. For each run this creates an `analysis` folder inside the run folder:
 
| File | Report part |
|---|---|
| `kem_table.csv`, `kem_table.md`, `kem_plot.png` | Part 2 (and Part 5) |
| `signature_table.csv`, `signature_table.md`, `signature_plot.png` | Part 3 (and Part 5) |
| `aead_table.csv`, `aead_table.md`, `aead_plot.png` | Part 4 (and Part 5), 16 rows |
 
All times are in milliseconds. The tables use the median and interquartile range (IQR) of the runs **after dropping the warm-up** (run 0), computed with `statistics.quantiles(n=4)`.
 
The `.md` files can be pasted into the report or turned into Word/LaTeX tables. The script prints a warning if any measurement does not have the number of runs it should (100, or 20 for RSA key generation). Fix that before trusting the numbers.