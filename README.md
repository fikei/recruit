# Agape recruiting viewer

Experimental applicant-triage viewer for the Agape recruiting pipeline, styled after the Ladder Inbox. Hosted at [recruit.ctrl.rodeo](https://recruit.ctrl.rodeo).

- **Data**: snapshot of the application Google Sheet, shipped AES-GCM-encrypted (`data/applicants.enc.json`); decrypted in-browser with the house passphrase (PBKDF2-SHA256, 310k iterations). No plaintext PII in this repo.
- **Decisions**: Outreach / Hold (with reason: fit, timing, current needs) / Pass — stored in `localStorage`, per-browser. Export CSV from the page ⋯ menu.
- **Stack**: vanilla JS/CSS, zero backend, GitHub Pages.

## Refresh the data

Re-export the sheet, run the parse + encrypt scripts (see `scripts/` note in session history), commit the new `applicants.enc.json`. Passphrase must stay the same or the house needs the new one.

Background: `agape-recruiting-pipeline-v1.md` (application → first interview process doc).
