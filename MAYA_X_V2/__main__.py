"""Offline MAYA inspect/build/verify; verified paired SUPER output."""
import argparse
import json

from .target import inventory


def main(argv=None):
    parser = argparse.ArgumentParser(prog='python -m MAYA_X_V2', description=__doc__)
    sub=parser.add_subparsers(dest='command',required=True)
    sub.add_parser('inspect')
    for command in ('build','verify'):
        child=sub.add_parser(command)
        child.add_argument('--output-dir',help='paired firmware directory; never a stock/recovery directory')
        child.add_argument('--profile',choices=('SUPER',),default='SUPER')
    args=parser.parse_args(argv)
    if args.command=='inspect':result=inventory()
    else:
        from .build import build,verify_exports
        result=(build if args.command=='build' else verify_exports)(args.output_dir,profile=args.profile)
    print(json.dumps(result,indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
