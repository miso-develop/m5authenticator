# Automatic Node.js / npm switching with fnm

This repository pins its Web toolchain to:

- Node.js `24.21.0`
- npm `11.19.0`

The repository root `.node-version` is the canonical Node.js version file. `web/package.json` also declares the exact Node.js/npm engines and `packageManager` metadata.

`fnm` manages Node.js versions, not npm versions independently. npm is installed inside each fnm-managed Node.js installation. Therefore the setup is:

1. install the Node.js version from `.node-version` with fnm;
2. install npm `11.19.0` once inside that Node.js installation;
3. initialize fnm with `--use-on-cd` so entering this repository automatically selects that Node.js installation and therefore its pinned npm.

## Windows one-time toolchain bootstrap

From the repository root in Command Prompt:

```bat
scripts\bootstrap_node_toolchain.cmd
```

The script:

- reads Node.js from `.node-version`;
- runs `fnm install` for that exact version;
- installs npm `11.19.0` only inside that fnm-managed Node.js installation;
- verifies `node --version` and `npm --version` through `fnm exec`.

It does not change `fnm default` and therefore does not change the user's persistent default Node.js version.

## Automatic switching in PowerShell

Add this once to the PowerShell profile:

```powershell
fnm env --use-on-cd --version-file-strategy recursive --shell powershell | Out-String | Invoke-Expression
```

The recursive version-file strategy allows direct navigation into subdirectories such as `web` while still resolving the repository-root `.node-version`.

After opening a new PowerShell window:

```powershell
cd <path-to-m5authenticator>\web
node --version
npm --version
```

Expected:

```text
v24.21.0
11.19.0
```

## Automatic switching in Windows Command Prompt

The repository includes:

```text
scripts\fnm_autorun.cmd
```

It initializes fnm using `--use-on-cd` and recursive `.node-version` lookup. Configure your Command Prompt / Windows Terminal startup to call this script once for each new shell.

For example, a Windows Terminal Command Prompt profile can start with:

```text
cmd.exe /k call "<path-to-m5authenticator>\scripts\fnm_autorun.cmd"
```

If you already use a Command Processor `AutoRun` script, call `scripts\fnm_autorun.cmd` from the existing startup script rather than replacing the existing AutoRun value.

The fnm initialization contains a guard because `FOR /F` starts another `cmd.exe` while evaluating `fnm env`.

After opening a new Command Prompt:

```bat
cd /d <path-to-m5authenticator>\web
node --version
npm --version
```

Expected:

```text
v24.21.0
11.19.0
```

## Normal Web commands

Once the automatic shell hook is configured, no explicit `fnm use` or `fnm exec` is needed for normal repository work:

```bat
cd /d <path-to-m5authenticator>\web
npm ci
npm test
npm run build
npm run dev
```

## Recovery / verification

If automatic switching is not active, verify fnm first:

```bat
fnm --version
fnm use --version-file-strategy recursive
node --version
npm --version
```

If Node.js is correct but npm is not `11.19.0`, rerun:

```bat
scripts\bootstrap_node_toolchain.cmd
```

Do not globally upgrade npm from inside the pinned Node.js `24.21.0` environment unless the repository pin is intentionally changed at the same time.
