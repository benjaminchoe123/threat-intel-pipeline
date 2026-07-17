# MISP setup (Tier 2)

Local MISP instance to receive the pipeline's STIX bundles (`vault/docs/stix/`, see
`pipeline/stix.py`) as events, via `pipeline/misp.py`. The Python side is built and
unit-tested; this doc is what's left, and needs a human at the keyboard for two steps
that require admin rights and a restart — Claude Code cannot do these non-interactively.

## 1. Enable WSL2 (admin PowerShell, one-time)

Windows 11 Home only supports Docker Desktop's WSL2 backend (no Hyper-V). Open
PowerShell **as Administrator** (right-click Start → "Terminal (Admin)") and run:

```powershell
wsl --install
```

**Restart the computer when it finishes.** This step needs elevation Claude Code's
shell doesn't have, and a reboot Claude Code can't safely trigger for you.

## 2. Install Docker Desktop

Download from https://www.docker.com/products/docker-desktop/ and run the installer
(or `winget install Docker.DockerDesktop` from an admin prompt). Launch it once, accept
the license terms, and confirm it's using the WSL2 backend (Settings → General).

## 3. Run MISP

```powershell
cd C:\Claude\threat-intel-pipeline
git clone https://github.com/MISP/misp-docker misp
cd misp
copy template.env .env
docker compose pull
docker compose up -d
```

The `misp/` folder is upstream's own repo (not vendored into this one — see
`.gitignore`). First startup takes a few minutes while MISP initializes its database.

Log in at **https://localhost** (self-signed cert — click through the browser warning):
- User: `admin@admin.test`
- Password: `admin`

**Change that password immediately** (top-right → My Profile → Change Password) — it's
a published default.

## 4. Get an API key and wire it in

In the MISP UI: top-right avatar → My Profile → Auth Keys → Add authentication key.
Copy the key, then add to `C:\Claude\threat-intel-pipeline\.env`:

```
MISP_URL=https://localhost
MISP_API_KEY=<the key you just generated>
MISP_VERIFY_SSL=false
```

(`MISP_VERIFY_SSL=false` because the default misp-docker cert is self-signed. Once
this points at a real cert, drop that line — verification defaults to on.)

## 5. Verify

```powershell
cd C:\Claude\threat-intel-pipeline
python -m pipeline.misp
```

This isn't a real command yet — the module currently only exposes `export_all()` for
`run.main()` to call automatically. For a one-off manual push while testing:

```powershell
python -c "from pipeline import config, misp; print(misp.export_all(config.VAULT_DIR))"
```

Check the MISP UI's Events list for the pushed events. From here, every future
`python -m pipeline.run` pushes new bundles automatically — `misp.export_all()` is
already wired into `run.main()`, gated on `MISP_URL`/`MISP_API_KEY` being set.

**This integration has not been live-verified against a real MISP instance** — only
against PyMISP's data-model classes, which don't need a server. Once you've completed
the steps above, tell Claude to run a real push and confirm the events look right in
the UI before trusting this in the daily/weekly automation.
