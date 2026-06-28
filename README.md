# Phishing Detection Tool

> **Academic / School Project — Educational Use Only**

A simple web-based tool (PHP) that demonstrates how a phishing detection
system can identify cloned/fake login pages by comparing them against a
known legitimate reference page.

## ⚠️ Important Note
All sample pages in `sample-sites/` are **fictional, self-made demo pages**
("Sample School Portal") created purely for testing this detector. They do
**not** represent any real company, bank, or institution. This project is
for learning cybersecurity concepts (phishing detection), not for creating
or distributing phishing content.

## How it works
The detector compares an **original** reference page against a **suspect**
page and checks for common phishing red flags:

1. **Content similarity** — how closely the HTML/text matches (clones are
   usually near-identical copies).
2. **Domain mismatch** — does the suspect page claim a different domain
   than the original?
3. **Lookalike domain detection** — simple check for character substitution
   tricks (e.g. `rn` instead of `m`, `1` instead of `l`).
4. **Suspicious form action** — where would submitted login data actually
   be sent? Phishing clones often redirect form submissions to an
   attacker-controlled server.

Based on these signals, the tool calculates a **risk score** and displays
a verdict on screen: `LIKELY SAFE`, `SUSPICIOUS - REVIEW MANUALLY`, or
`PHISHING SUSPECTED`.

## Project structure
```
phishing-detection-tool/
├── sample-sites/
│   ├── original_portal.html   # fictional "legitimate" sample page
│   └── cloned_portal.html     # fictional "phishing clone" sample page
├── detector/
│   ├── PhishingDetector.php   # core detection logic
│   └── index.php              # web UI - run check, see result on screen
└── README.md
```

## How to run
1. Make sure PHP is installed (`php -v` to check).
2. From the project root, start PHP's built-in server:
   ```
   cd detector
   php -S localhost:8000
   ```
3. Open `http://localhost:8000` in your browser.
4. Click **"Run Detection Check"** to see the analysis result on screen.

## Possible extensions (for further coursework)
- Allow file upload of any two HTML pages instead of fixed samples.
- Add screenshot/visual similarity comparison.
- Add SSL certificate validation check.
- Maintain a whitelist/blacklist database of known legitimate domains.
