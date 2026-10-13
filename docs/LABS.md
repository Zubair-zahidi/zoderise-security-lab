# Local lab exercises

These exercises use a folder and web server you control. Record what you expected, what happened, and what the result cannot establish.

## 1. File-integrity observation

Create `lab-files` and place two plain-text sample files in it. Run:

```bash
python security_lab.py baseline ./lab-files --output ./baseline.json
python security_lab.py verify ./lab-files --baseline ./baseline.json
```

Change one sample file, delete the other, and add a new sample. Verify again. Compare the `modified`, `removed`, and `added` lists with your actions.

Questions: Does a changed hash tell you why a file changed? What happens if an attacker can also replace the baseline? A digest comparison is an observation, not proof of malicious activity. Keep an original baseline separately when integrity matters.

## 2. Local HTTP response review

In a directory containing only public test files, start a loopback-only server:

```bash
python -m http.server 8000 --bind 127.0.0.1
```

In a second terminal:

```bash
python security_lab.py headers http://127.0.0.1:8000/
```

Inspect which checks are false. A simple development server is not configured like a hardened application. Explain which headers a real application may need and why their values must fit the application's behavior. Header presence alone does not demonstrate a secure policy.

Stop the test server when finished. The reviewer rejects non-loopback addresses and refuses redirects.

## 3. POSIX permissions

On Linux, create a disposable sample in your own lab directory:

```bash
mkdir -p lab-files
touch lab-files/example.txt
chmod o+w lab-files/example.txt
python security_lab.py permissions ./lab-files
chmod o-w lab-files/example.txt
```

Review the finding and run the check again after restoring the permission. These commands affect only your sample file. Do not apply blanket permission changes to system or application directories.

Questions: When can group-write permission be appropriate? What does this utility miss about ACLs, file ownership, running processes, and directory access?

## 4. Explain a finding

Use [the report template](REPORT_TEMPLATE.md) to describe one lab observation. Separate evidence, interpretation, and remediation. Include your scope and retest result, and state uncertainties.
