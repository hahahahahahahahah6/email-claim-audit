"""Command-line interface."""
import argparse
import json
import sys
from . import __version__
from .core import audit


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError(message)


def main(argv=None):
    parser = Parser(description='Audit documented outbound-mail promises.')
    parser.add_argument('root', nargs='?', default='.')
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--verbose', action='store_true')
    parser.add_argument('--ignore', nargs='+', action='extend', default=[])
    parser.add_argument('--fail-on', choices=['HIGH', 'MEDIUM'], default='MEDIUM')
    parser.add_argument('--version', action='store_true')
    try:
        args = parser.parse_args(argv)
        if args.version:
            print(__version__)
            return 0
        result = audit(args.root, args.ignore, args.fail_on)
    except (ValueError, OSError, UnicodeError) as exc:
        print('error: ' + str(exc), file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(result['status'])
        for finding in result['findings']:
            line = finding['rule'] + ' ' + finding['severity']
            if args.verbose:
                line += ' ' + finding['path']
            print(line)
        if args.verbose:
            for item in result['evidence']:
                print('evidence: {path}:{line} {channel}'.format(**item))
    return 2 if result['status'] == 'FAIL' else 0
