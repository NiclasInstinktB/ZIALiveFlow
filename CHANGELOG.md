# Changelog

Newest version first. Versions are tagged `vX.Y.Z`, the middle number goes up for
features, the last one for fixes in between.

## v0.49.3

- deploy/venv.sh only warns when the newest Python on the host is below 3.11, the minimum the dependencies support. It used to warn on every update below 3.15, which most distributions do not ship yet.
- README and DEPLOY.md ask for Python 3.11 or newer, the newest your distribution ships. Moving the venv to a newer Python stays automatic.

## v0.49.2

Frontend packages on current versions, npm audit is clean again.

- vite 8.3.5 fixes the two high severity advisories in vite and source-map-js.
- react and react-dom 19.3.1, i18next 26.7.1, react-i18next 17.1.12, i18next-browser-languagedetector 8.3.0, @vitejs/plugin-react 6.2.1, @types/react and @types/react-dom 19.3.0.

## v0.49.1

- .gitignore covers .venv.new and .venv.old, the temporary folders deploy/venv.sh uses while it swaps the venv. A leftover one no longer marks the install as dirty in the update panel.

## v0.49.0

Server installs move to the newest Python by themselves.

- New deploy/venv.sh, used by setup.sh and update.sh. It picks the newest python3.x on PATH instead of preferring python3.12. PYTHON=... still overrides it.
- If the venv runs on an older Python than the newest one installed, the next update builds a new venv next to it and swaps it in only after every dependency installed. A failed build keeps the old venv.
- A venv whose base Python got uninstalled is rebuilt instead of left broken.
- The update log warns while the host has nothing newer than Python 3.14.
- pyyaml is built as plain Python, since there is no wheel for Python 3.15 yet and servers usually have no compiler.
- install.py rebuilds an existing venv that is older than the Python running it.
- README and DEPLOY.md name Python 3.15.

## v0.48.2

Dependencies on current versions, runs on Python 3.15.

- fastapi 0.162.0, uvicorn 0.54.0, websockets 17.4, pydantic 2.14.2, pydantic-settings 2.16.2, PyJWT 2.15.1, cryptography 50.0.2, tzdata 2026.6, pytest 9.2.0, pytest-asyncio 1.4.1.post1.
- pydantic 2.13.4 had no wheel for Python 3.15, 2.14.2 has one.
- Fixed a ring buffer test that failed on Python 3.13 and newer under Windows. The more precise clock put the record exactly on the age boundary just past it.

## v0.48.1

Feed buttons no longer reset the live flow.

- Switching Web, FW or DNS off hides those records instead of clearing the view. The other rows stay.
- Switching a feed back on shows its earlier records again. Lines that came in while it was off are not collected.
- An open detail row stays open if the record is still there.
- Changing the actual filter still starts the view over, like before.

## v0.48.0

Live flow filter takes IP ranges and lists.

- Source and destination IP accept ranges like 10.20.30.10-10.20.30.50 or the short form 10.20.30.10-50. Swapped bounds get turned around.
- A range covers at most 512 addresses, about a /23. Larger ones are rejected in the form and dropped by the server.
- Several IPs separated by commas or semicolons become separate chips in the same group (OR) and mix with CIDR and ranges. The error names the part that failed.
- New error messages in all 9 languages, placeholder updated.

## v0.47.0

Audit of the whole codebase, 36 fixes. Two behaviours changed on purpose.

Critical
- An unreadable admins.json wiped every account in memory, and the next write persisted the wipe.
- Revoking clear text mid-stream masked the fields but left the user filter running, so every masked record still belonged to one named person.
- A first start could create the account, fail on the group and leave the install locked out for good.
- A config file that parsed to anything other than an object crashed startup.

Security
- The login brake keyed on X-Forwarded-For, so rotating the header defeated it and decided what the audit log recorded.
- CORS set to * still sent credentials.
- The directory lookup did not escape the identity.
- An account manager could disable, delete or repassword a superadmin account.
- A directory session could renew itself past a full revocation.
- A throttled login was not audited.

Data loss
- Saving one config field wrote all of them, which froze the env file from then on.
- A stat based signature let a CLI revocation be clobbered by the running service.
- A JWT rotation overwrote the env fallback password with an empty string.
- A failed prefs load armed the autosave and overwrote the stored prefs with defaults.
- Several rejected writes left memory and disk disagreeing.

Correctness
- A rejected filter group silently widened an AND join, so you saw traffic you had excluded.
- The ingest allowlist refused IPv4 feeds on a dual stack listener.
- An overlong line delivered its tail as a line of its own.
- A timestamp of non decimal digits dropped the whole record instead of arriving unreadable.
- One binary WebSocket frame wedged the live stream for good.

Behaviour changes
- A directory session now lives at most one full lifetime counted from sign in, then requires a new sign-in. Local sessions are unchanged.
- The two settings panels save and reset only their own fields.

428 tests, up from 234.

## v0.46.1

Two fixes in how runtime settings are persisted.

- Saving a setting wrote the complete settings set to runtime_settings.json, so the first
  save froze every value from the env file into it. Editing the env file afterwards had no
  effect and nothing said so. The file now records only the keys an operator actually
  changed.
- Updating validated and assigned in the same pass, so a batch with an invalid value at the
  end left the earlier values applied in memory while the caller got an error and nothing
  was written. The whole batch is validated first now, then applied, or nothing is.
- Values that do not differ from the current one are no longer written.
- A corrupt or non-object override file is ignored instead of being half read.
- 11 new tests, 234 in total.

## v0.46.0

First public release.

- Three NSS feeds over TCP: web on 5140, firewall on 5141, DNS on 5142. Port 0 turns a feed off.
- Positional prefilter on the first five fields, everything else is dropped without parsing.
- One table for all three feeds, colour-coded by verdict.
- Feeds can be switched on and off per view, takes effect server side.
- Feed badge with three states: no data, running, silent for X.
- Dead connection detection, TCP keepalive plus an idle timeout.
- Retention in RAM only, nothing is written to disk.
- Own filter, buffer and stream per user, several people can work at the same time.
- Query search over the flows on screen, wildcards and autocompletion.
- Query chips, personal and global.
- Local accounts, optional AD/LDAP, optional OpenID Connect.
- Permissions attach to groups, no roles. You can only grant what you hold yourself.
- Anonymised log view, masked on the server, user filter locked.
- Audit log for sign-ins and searches, metadata only.
- 34 settings editable in the admin backend, split into live and restart.
- 9 interface languages.
- Self-update from git, triggered from the admin backend.
- Runs on Windows, Linux and macOS. serve.py reads the stored settings before binding.
- 223 tests.
