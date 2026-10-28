# Changelog

Newest version first. Versions are tagged `vX.Y.Z`, the middle number goes up for
features, the last one for fixes in between.

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
