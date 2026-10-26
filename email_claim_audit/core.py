"""Static checks for documented outbound-mail promises."""
import ast
import fnmatch
import os
import re
from pathlib import Path

EMAIL = (
    'sends email notifications', 'sends email alerts',
    'sends notifications via email', 'sends alerts via email',
    'supports email notifications', 'supports email alerts',
    'delivers email notifications', 'delivers email alerts',
    'notifies via email', 'notifies by email', 'sends emails', 'sends email',
    'email notifications', 'email alerts', 'can send email', 'can send emails',
    'emails you',
)
NOEMAIL = (
    'does not send email notifications', 'does not send email alerts',
    'does not send email', 'does not send emails', 'never sends email',
    'never sends emails', 'does not notify via email', 'does not notify by email',
    'no email notifications', 'no email alerts',
)


def pattern(phrases):
    return re.compile(r'\b(?:' + '|'.join(re.escape(p) for p in sorted(phrases, key=len, reverse=True)) + r')\b')


def prose(text):
    """Remove Markdown fences and preserve paragraph boundaries."""
    lines = []
    fence = None
    for line in text.splitlines():
        match = re.match(r'^\s{0,3}(`{3,}|~{3,})', line)
        if fence:
            if match and match[1][0] == fence[0] and len(match[1]) >= len(fence) and not line[match.end():].strip():
                fence = None
            lines.append('')
        elif match:
            fence = match[1]
            lines.append('')
        else:
            lines.append(line)
    for paragraph in re.split(r'\n\s*\n', '\n'.join(lines)):
        yield re.sub(r'\s+', ' ', paragraph.lower().replace("n't", ' not').replace('-', ' '))


def dotted(node, aliases):
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        return dotted(node.value, aliases) + '.' + node.attr
    return ''


def send_evidence(tree):
    imports = set()
    aliases = {}
    nodes = list(ast.walk(tree))
    for node in nodes:
        if isinstance(node, ast.Import):
            for item in node.names:
                imports.add(item.name.split('.')[0])
                aliases[item.asname or item.name.split('.')[0]] = item.name if item.asname else item.name.split('.')[0]
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split('.')[0])
            for item in node.names:
                aliases[item.asname or item.name] = node.module + '.' + item.name
    providers = {'SendGridAPIClient': 'sendgrid', 'Mail': 'flask_mail',
                 'EmailMessage': 'django', 'EmailMultiAlternatives': 'django'}

    def constructor(node):
        if not isinstance(node, ast.Call):
            return False
        name = dotted(node.func, aliases).split('.')[-1]
        return name in providers and providers[name] in imports

    bindings = set()
    for node in nodes:
        if isinstance(node, ast.Assign) and constructor(node.value):
            bindings.update(t.id for t in node.targets if isinstance(t, ast.Name))
        elif isinstance(node, ast.AnnAssign) and constructor(node.value) and isinstance(node.target, ast.Name):
            bindings.add(node.target.id)
    found = []
    for node in nodes:
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        channel = None
        if isinstance(func, ast.Attribute):
            if func.attr in ('sendmail', 'send_message'):
                channel = 'smtplib'
            elif func.attr in ('send_email', 'send_raw_email') and imports & {'boto3', 'botocore'}:
                channel = 'ses'
            elif func.attr == 'send':
                if dotted(func.value, aliases) == 'aiosmtplib' and 'aiosmtplib' in imports:
                    channel = 'aiosmtplib'
                elif constructor(func.value) or isinstance(func.value, ast.Name) and func.value.id in bindings:
                    channel = 'provider'
        elif isinstance(func, ast.Name) and 'django' in imports and dotted(func, aliases).split('.')[-1] in ('send_mail', 'send_mass_mail'):
            channel = 'django'
        if channel:
            found.append({'line': node.lineno, 'channel': channel})
    return found


def audit(root, ignore=(), fail_on='MEDIUM'):
    root = Path(root)
    if not root.is_dir():
        raise ValueError('ROOT must be an existing directory')
    claims = []
    evidence = []
    for directory, dirs, files in os.walk(root, followlinks=False):
        base = Path(directory)

        def excluded(path):
            rel = path.relative_to(root).as_posix()
            return path.is_symlink() or any(fnmatch.fnmatchcase(rel, p) for p in ignore)

        dirs[:] = sorted(d for d in dirs if not excluded(base / d))
        for name in sorted(files):
            path = base / name
            if excluded(path):
                continue
            rel = path.relative_to(root)
            parts = rel.parts
            if rel.as_posix() == 'README.md' or path.suffix.lower() == '.md' and 'docs' in parts[:-1]:
                for paragraph in prose(path.read_text(encoding='utf-8')):
                    negative = pattern(NOEMAIL)
                    if negative.search(paragraph):
                        claims.append({'family': 'NOEMAIL', 'path': rel.as_posix(), 'severity': 'MEDIUM' if 'tests' in parts[:-1] else 'HIGH'})
                    if pattern(EMAIL).search(negative.sub(' ', paragraph)):
                        claims.append({'family': 'EMAIL', 'path': rel.as_posix(), 'severity': 'MEDIUM' if 'tests' in parts[:-1] else 'HIGH'})
            if path.suffix == '.py' and 'tests' not in parts[:-1] and not name.startswith('test_'):
                try:
                    tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(rel))
                except SyntaxError as exc:
                    raise ValueError('Invalid Python source: ' + str(rel)) from exc
                evidence.extend(dict(item, path=rel.as_posix()) for item in send_evidence(tree))
    findings = []
    for family, contradicted, rule in (
        ('EMAIL', not evidence, 'documented-email-claim-false'),
        ('NOEMAIL', bool(evidence), 'documented-no-email-claim-false'),
    ):
        matches = [c for c in claims if c['family'] == family]
        if matches and contradicted:
            claim = sorted(matches, key=lambda c: (c['severity'] != 'HIGH', c['path']))[0]
            findings.append({'rule': rule, 'severity': claim['severity'], 'path': claim['path']})
    failed = any(fail_on == 'MEDIUM' or f['severity'] == 'HIGH' for f in findings)
    return {'status': 'FAIL' if failed else 'PASS', 'evidence': evidence, 'claims': claims, 'findings': findings}
