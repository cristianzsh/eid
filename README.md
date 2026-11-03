# eid

Quick lookup of Windows event IDs from the command line, made for forensics and incident response.

```
$ eid 4624
security  4624  An account was successfully logged on

$ eid 7045
system    7045  A new service was installed in the system. (4697 in Security)
```

## Usage

```
eid 4768                 # meaning of event 4768 in every source
eid 4624 4672 4688       # several IDs at once
eid "46*"                # wildcard, quote it so the shell does not expand it
eid --sysmon 1           # restrict the search to one source
eid -s locked            # search descriptions by text
eid --rdp -s logon       # search descriptions by text in one source
eid --list               # sources, event counts and the log file each one lives in
eid --list security      # every event of a source
```

Without the binary, run `python3 eid.py` instead of `eid`.

## Sources

Run `eid --list` to see them. Each source maps to a Windows log channel and shows the `.evtx` file name, for example:

```
security       574  Windows Security log
                    Security.evtx
system          31  Windows System log
                    System.evtx
application     27  Windows Application log
                    Application.evtx
sysmon          30  Sysmon operational log
                    Microsoft-Windows-Sysmon%4Operational.evtx
...
```

## Adding events and sources

Everything lives in `data/`:

- `data/<source>.csv` has two columns, `id,description`. To add an event, append a line.
- `data/sources.csv` has three columns, `name,description,files`. To add a source, create `data/<name>.csv` and add one line here. The flag `--<name>` and `--list <name>` start working immediately.

No code changes are needed, just rebuild the binary afterwards.

## Building a binary

Requires Python 3 and pip. PyInstaller is installed automatically.

```
./build.sh      # Linux, produces dist/eid
build.bat       # Windows, produces dist\eid.exe
```

The data folder is embedded in the binary, so `dist/eid` can be copied anywhere on its own.

## License

`eid` is released under the MIT License. See [LICENSE](LICENSE).
