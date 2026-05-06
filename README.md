# decrypt_ha_logs

Downloads recent Home Assistant report archives from Robonomics datalog records,
decrypts them, and stores the decrypted files in a directory tree that is easy
to inspect.

## Configuration

Copy `creds.yaml.example` to `creds.yaml` and fill in the recipient seed and
sender addresses.

```yaml
recipient_seed: "..."

sender_addresses:
  - address: "..."
    name: "home-a"
  - address: "..."
    name: "home-b"

reports_per_address: 2
reports_dir: reports
clean_reports: true
ipfs_gateway: https://ipfs.io
network_wss: wss://polkadot.rpc.robonomics.network/
```

## Installation

Create a virtual environment in the project directory:

```bash
python3 -m venv .venv
```

Activate it:

```bash
source .venv/bin/activate
```

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

## Usage

```bash
.venv/bin/python decrypt_ha_logs.py
```

Use another config file:

```bash
.venv/bin/python decrypt_ha_logs.py --creds /path/to/creds.yaml
```

By default, `reports_dir` is cleaned before every run. Decrypted reports are
stored like this:

```text
reports/
  home-a/
    datalog_16_1710000000/
      cid.txt
      home-assistant.log
      issue_description.json
      trace.saved_traces
```
