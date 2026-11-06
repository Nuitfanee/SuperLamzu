"""Explicit host entry points; help and patch dispatch never open HID."""
import importlib
import sys


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help", "help"):
        print("Usage: python -m superlamzu {cfg|patch|fw|soak} ...\n"
              "  cfg    LAMZU native configuration and SLZ1 extensions\n"
              "  patch  offline SUPER daily-use firmware builder\n"
              "  fw     offline HEX inspection or read-only APP info/list\n"
              "  soak   explicit read-only stability logs, summary and comparison\n"
              "Start configuration:\n"
              "  python -m superlamzu cfg list\n"
              "  python -m superlamzu cfg show\n"
              "  python -m superlamzu cfg --help\n"
              "Run a subcommand with --help for its options.\n"
              "Firmware installation and stock recovery: use the matching executable in flasher/.")
        return 0
    command, rest = argv[0], argv[1:]
    if command not in ("cfg", "patch", "fw", "soak"):
        print(f"unknown command {command!r}; choose cfg, patch, fw or soak", file=sys.stderr)
        return 2
    module = importlib.import_module(f"superlamzu.{command}")
    return module.main(rest)


if __name__ == "__main__":
    raise SystemExit(main())
