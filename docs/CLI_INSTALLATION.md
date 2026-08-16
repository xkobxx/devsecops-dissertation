# CLI Installation

TrustGate is a local-first application security decision platform distributed as a Python CLI tool.

## Requirements

- Python 3.10 or later
- pip 21.0 or later

## Install with pip

```bash
pip install trustgate
```

## Install with pipx (recommended)

[pipx](https://pypa.github.io/pipx/) installs TrustGate in an isolated environment while making the `trustgate` command globally available.

```bash
pipx install trustgate
```

To upgrade later:

```bash
pipx upgrade trustgate
```

## Install from source

```bash
git clone https://github.com/your-org/trustgate.git
cd trustgate
pip install -e .
```

The `-e` flag installs in editable mode so local changes take effect immediately.

## Verify installation

```bash
trustgate --version
```

You should see output like `trustgate 0.1.0`. If the command is not found, ensure your Python scripts directory is on your `PATH`.

## Shell completion

TrustGate supports tab completion for commands, options, and arguments.

### Bash

```bash
echo 'eval "$(_TRUSTGATE_COMPLETE=bash_source trustgate)"' >> ~/.bashrc
source ~/.bashrc
```

### Zsh

```bash
echo 'eval "$(_TRUSTGATE_COMPLETE=zsh_source trustgate)"' >> ~/.zshrc
source ~/.zshrc
```

### Fish

```bash
_TRUSTGATE_COMPLETE=fish_source trustgate > ~/.config/fish/completions/trustgate.fish
```

After setup, press `Tab` to autocomplete commands and options.

## Troubleshooting

| Problem | Fix |
|---|---|
| `command not found` | Add your Python scripts directory to `PATH` |
| Permission errors | Use `pip install --user trustgate` or switch to pipx |
| Conflicts with other packages | Use pipx or a virtual environment |
