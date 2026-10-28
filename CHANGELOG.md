# Changelog

Newest version first. Versions are tagged `vX.Y.Z`, the middle number goes up for
features, the last one for fixes in between.

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
