import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from email_claim_audit.core import audit, EMAIL, NOEMAIL
from email_claim_audit.cli import main


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')
        return path

    def fixture(self, source=None, claim='sends email alerts', doc='README.md'):
        self.write(doc, claim)
        if source is not None:
            self.write('app.py', source)
        return audit(self.root)

    def good(self, source):
        result = self.fixture(source)
        self.assertEqual(result['status'], 'PASS')
        self.assertTrue(result['evidence'])
        self.assertEqual(result['findings'], [])

    def bad(self, source=None):
        result = self.fixture(source)
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['evidence'], [])
        self.assertEqual(result['findings'], [{'rule': 'documented-email-claim-false', 'severity': 'HIGH', 'path': 'README.md'}])

    def test_good_smtplib_sendmail(self):
        self.good('smtp.sendmail(a, b, c)')

    def test_good_smtplib_send_message(self):
        self.good('smtplib.SMTP(host).send_message(msg)')

    def test_good_ses_send_email(self):
        self.good('import boto3 as b\nc = b.client("ses")\nc.send_email()')

    def test_good_ses_send_raw_email(self):
        self.good('from botocore import session\nc.send_raw_email()')

    def test_good_sendgrid_binding(self):
        self.good('from sendgrid import SendGridAPIClient as Client\nsg = Client(key)\nsg.send(msg)')

    def test_good_django_send_mail(self):
        self.good('from django.core.mail import send_mail\nsend_mail()')

    def test_good_django_email_message_direct(self):
        self.good('from django.core.mail import EmailMessage\nEmailMessage().send()')

    def test_good_django_email_message_binding(self):
        self.good('from django.core.mail import EmailMessage\nmessage = EmailMessage()\nmessage.send()')

    def test_good_flask_mail(self):
        self.good('from flask_mail import Mail\nmail = Mail(app)\nmail.send(msg)')

    def test_good_aiosmtplib(self):
        self.good('import aiosmtplib as smtp\nsmtp.send(msg)')

    def test_bad_import_only_smtplib(self):
        self.bad('import smtplib\nimport boto3\nimport sendgrid\nimport django.core.mail\nimport flask_mail\nimport aiosmtplib')

    def test_bad_smtp_construction(self):
        self.bad('import smtplib\nsmtp = smtplib.SMTP(host)')

    def test_bad_validation_regex(self):
        self.bad('import re\nre.match(r"[^@]+@[^@]+", address)')

    def test_bad_mime_format(self):
        self.bad('from email.mime.text import MIMEText\nfrom email.mime.multipart import MIMEMultipart\nfrom django.core.mail import EmailMessage\nMIMEText(body)\nMIMEMultipart()\nEmailMessage()\nsubject = "To: {}".format(address)')

    def test_bad_stub_send_email(self):
        self.bad('def send_email():\n    pass\ndef send_mail():\n    raise RuntimeError("stub")')

    def test_bad_send_email_without_boto3(self):
        self.bad('client.send_email()\nclient.send_raw_email()')

    def test_bad_socket_send(self):
        self.bad('import socket\nsock = socket.socket()\nsock.send(msg)')

    def test_bad_unbound_send_with_sendgrid(self):
        self.bad('import sendgrid\nclient.send(msg)')

    def test_bad_comment_docstring_string(self):
        self.bad('# smtp.sendmail()\n"""smtp.send_message()"""\nx = "sendmail"')

    def test_bad_claim_no_source_high(self):
        self.bad()

    def test_good_negative_no_source(self):
        self.assertEqual(self.fixture(claim='does not send email')['status'], 'PASS')

    def test_good_negative_no_evidence(self):
        result = self.fixture('import smtplib', 'does not send email')
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual({c['family'] for c in result['claims']}, {'NOEMAIL'})

    def test_bad_negative_with_evidence(self):
        result = self.fixture('smtp.sendmail()', 'does not send email')
        self.assertEqual(result['findings'], [{'rule': 'documented-no-email-claim-false', 'severity': 'HIGH', 'path': 'README.md'}])

    def test_testonly_medium_threshold(self):
        self.write('tests/docs/guide.md', 'sends email alerts')
        self.write('tests/sender.py', 'smtp.sendmail()')
        self.write('test_sender.py', 'smtp.send_message()')
        self.assertEqual(audit(self.root)['findings'][0]['severity'], 'MEDIUM')
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main([str(self.root), '--fail-on', 'HIGH']), 0)

    def test_fenced_code_exclusion(self):
        result = self.fixture(claim='```text\nsends email alerts\n```\n\n~~~\nnever sends email\n~~~')
        self.assertEqual(result['claims'], [])

    def test_inline_code_counts(self):
        self.assertEqual(self.fixture(claim='It `sends email alerts`.')['status'], 'FAIL')

    def test_paragraph_line_joining(self):
        self.assertEqual(self.fixture(claim='It sends\nemail alerts.')['status'], 'FAIL')
        self.assertEqual(self.fixture(claim='It sends\n\nemail messages.')['claims'], [])

    def test_word_boundary(self):
        self.assertEqual(self.fixture(claim='sends emailsystem; emails yourself; email alertsystem')['claims'], [])

    def test_usage_error_exit_one(self):
        with contextlib.redirect_stderr(io.StringIO()):
            for args in (['--unknown'], ['--fail-on', 'LOW'], [str(self.root / 'missing')]):
                self.assertEqual(main(args), 1)

    def test_json_shape(self):
        self.fixture('import smtplib')
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(main([str(self.root), '--json']), 2)
        result = json.loads(out.getvalue())
        self.assertEqual(set(result), {'status', 'claims', 'evidence', 'findings'})
        self.assertEqual(set(result['findings'][0]), {'rule', 'severity', 'path'})

    def test_self_audit(self):
        result = audit(Path(__file__).resolve().parents[1])
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual(result['claims'], [])

    def test_all_exact_templates(self):
        for phrase in EMAIL:
            with self.subTest(phrase=phrase):
                self.assertEqual(self.fixture(claim=phrase)['claims'][0]['family'], 'EMAIL')
        for phrase in NOEMAIL:
            with self.subTest(phrase=phrase):
                self.assertEqual({c['family'] for c in self.fixture(claim=phrase)['claims']}, {'NOEMAIL'})

    def test_normalization_and_no_generic_negation(self):
        self.assertEqual(self.fixture(claim="doesn't send-email")['claims'][0]['family'], 'NOEMAIL')
        self.assertEqual(self.fixture(claim='Sends email notifications, does not require a mail server')['status'], 'FAIL')

    def test_ambiguous_and_bare_nouns(self):
        self.assertEqual(self.fixture(claim='email support; contact us by email; email address; email; emails; mail; notification; alert')['claims'], [])

    def test_ignore_directory_and_glob(self):
        self.write('docs/deep/claim.md', 'sends emails')
        self.write('README.md', 'sends emails')
        self.assertEqual(audit(self.root, ['docs', 'README.*'])['claims'], [])

    def test_symlinks_skipped(self):
        outside = self.write('outside.txt', 'sends emails')
        (self.root / 'README.md').symlink_to(outside)
        (self.root / 'docs').symlink_to(self.root, target_is_directory=True)
        self.assertEqual(audit(self.root)['claims'], [])

    def test_environment_never_opened(self):
        marker = Path(__file__).parent / 'fixtures' / '.env'
        self.write('.env', marker.read_text())
        original = Path.open
        def guarded(path, *args, **kwargs):
            self.assertNotEqual(path.name, '.env')
            return original(path, *args, **kwargs)
        with patch.object(Path, 'open', guarded):
            self.assertEqual(audit(self.root)['status'], 'PASS')

    def test_other_provider_variants(self):
        self.good('from sendgrid import SendGridAPIClient\nSendGridAPIClient().send(msg)\nfrom django.core.mail import EmailMultiAlternatives, send_mass_mail\nEmailMultiAlternatives().send()\nsend_mass_mail(data)')
        self.assertEqual(len(audit(self.root)['evidence']), 3)

    def test_one_finding_per_family_and_production_priority(self):
        self.write('tests/docs/test.md', 'sends emails')
        self.write('docs/manual.md', 'sends emails\n\nsends email alerts')
        result = audit(self.root)
        self.assertEqual(len(result['findings']), 1)
        self.assertEqual(result['findings'][0]['severity'], 'HIGH')

    def test_invalid_source_input_error(self):
        self.write('app.py', 'def broken(')
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main([str(self.root)]), 1)

    def test_version_and_verbose(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(main(['--version']), 0)
        self.assertEqual(out.getvalue(), '0.1.0\n')
        self.fixture()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(main([str(self.root), '--verbose']), 2)
        self.assertIn('documented-email-claim-false HIGH README.md', out.getvalue())


if __name__ == '__main__':
    unittest.main()
