# email-claim-audit

A stdlib-only static auditor for documented mail-delivery promises. Requires
Python 3.9 or newer. Source is parsed with the AST and is never executed.
Environment dotfiles are never opened; the marker-only fixture guards this rule.

Install and run:

```sh
python3 -m pip install .
email-claim-audit . --json
python3 -m email_claim_audit . --verbose
python3 -m unittest discover
python3 -m build
```

The CLI accepts an optional root (default current directory), `--json`,
`--verbose`, `--ignore GLOB ...`, `--fail-on HIGH|MEDIUM`, and `--version`.
Ignore patterns match POSIX relative paths using fnmatch; ignored directories
exclude their descendants. Symlinks are skipped. Input or argument errors return
1; findings at the selected threshold return 2; otherwise the exit code is 0.
The default threshold is MEDIUM. Version output is 0.1.0.

Root README.md and Markdown files with a docs path component supply claims.
Fenced blocks are excluded; inline code counts. Paragraph lines are joined,
text is lowercased, contractions are expanded, hyphens become spaces, and
whitespace is collapsed. Exact word boundaries apply. Negative spans are removed
before positive matching; there is no additional sentence-negation suppression.
Bare nouns and ambiguous support-channel or address wording do not count.

Positive templates:

```text
sends email notifications
sends email alerts
sends notifications via email
sends alerts via email
supports email notifications
supports email alerts
delivers email notifications
delivers email alerts
notifies via email
notifies by email
sends emails
sends email
email notifications
email alerts
can send email
can send emails
emails you
```

Negative templates:

```text
does not send email notifications
does not send email alerts
does not send email
does not send emails
never sends email
never sends emails
does not notify via email
does not notify by email
no email notifications
no email alerts
```

Each family produces at most one finding. Production documentation has HIGH
severity; claims confined to tests/docs have MEDIUM severity. A positive promise
without a matching call fails, including when there is no source. A negative
promise fails only when a matching call exists. With no claim the result passes.
Rule identifiers:

```text
documented-email-claim-false
documented-no-email-claim-false
```

JSON contains status, evidence, claims, and findings. Each finding includes rule,
severity, and path. Text starts with PASS or FAIL, followed by rule and severity
for each finding; verbose output adds paths and call evidence.

Evidence is a call in a production .py file, excluding tests directories and
files named test_*.py. Comments, docstrings, literals, bare method names, imports,
address validation, message formatting, and client construction alone do not count.
The supported calls are:

```text
any_receiver.sendmail(...), any_receiver.send_message(...)
client.send_email(...), client.send_raw_email(...) with boto3/botocore imported
SendGridAPIClient(...).send(...) with sendgrid imported
Mail(...).send(...) with flask_mail imported
EmailMessage(...).send(...), EmailMultiAlternatives(...).send(...) with django imported
send_mail(...), send_mass_mail(...) with django imported
aiosmtplib.send(...) with aiosmtplib imported
```

Provider send methods also count on names assigned directly from the listed
constructors in the same module. Import aliases are resolved per module. Generic
socket, queue, unbound client, and local wrapper calls do not establish evidence.

Coverage is intentionally limited to smtplib, SES via boto3/botocore, SendGrid,
Django mail, Flask-Mail, and aiosmtplib. Mailgun/Resend/Mailjet HTTP APIs,
raw-socket SMTP, and other providers' SDKs are out of scope in 0.1.0. Results
cannot establish behavior for those channels. Static matching is not semantics:
a call in dead code or behind a never-true condition still counts. Dynamic
dispatch such as getattr-based calls is not detected.

The project audits its own clean tree with PASS and no claim. MIT licensed.
