import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "opn_config_cleaner.py"
SYNTHETIC_XML = b"""<?xml version=\"1.0\"?>
<opnsense>
  <system><password>synthetic-secret</password></system>
  <dyndns><username>synthetic-user</username></dyndns>
  <geoip><url>https://example.invalid/?license_key=synthetic</url></geoip>
  <revision><username>audit-user</username><description>keep this</description></revision>
</opnsense>
"""


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.directory = Path(self.temp_dir.name)
        self.input_path = self.directory / "synthetic.xml"
        self.input_path.write_bytes(SYNTHETIC_XML)

    def run_cli(self, *args):
        # Make CLI tests fail if the command imports Tkinter at any point.
        code = "\n".join(
            [
                "import builtins, runpy, sys",
                "original_import = builtins.__import__",
                "def guarded_import(name, *args, **kwargs):",
                "    if name == 'tkinter' or name.startswith('tkinter.'):",
                "        raise AssertionError('Tkinter imported by CLI')",
                "    return original_import(name, *args, **kwargs)",
                "builtins.__import__ = guarded_import",
                "sys.argv = [sys.argv[1], *sys.argv[2:]]",
                "runpy.run_path(sys.argv[0], run_name='__main__')",
            ]
        )
        environment = os.environ.copy()
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        return subprocess.run(
            [sys.executable, "-c", code, str(SCRIPT), *map(str, args)],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_sanitizes_and_writes_counts_only_json_without_tkinter(self):
        output_path = self.directory / "sanitized.xml"
        report_path = self.directory / "report.json"
        original_bytes = self.input_path.read_bytes()

        result = self.run_cli(
            "--input", self.input_path,
            "--output", output_path,
            "--report", report_path,
            "--strip-audit-usernames",
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Sanitization complete", result.stdout)
        self.assertEqual(self.input_path.read_bytes(), original_bytes)
        sanitized = output_path.read_text(encoding="utf-8")
        self.assertNotIn("synthetic-secret", sanitized)
        self.assertNotIn("synthetic-user", sanitized)
        self.assertNotIn("license_key=synthetic", sanitized)
        self.assertNotIn("audit-user", sanitized)
        self.assertIn("keep this", sanitized)
        self.assertEqual(
            json.loads(report_path.read_text(encoding="utf-8")),
            {
                "secret_fields": 1,
                "credential_usernames": 1,
                "geoip_urls": 1,
                "audit_usernames": 1,
            },
        )

    def test_refuses_input_alias_and_preserves_original(self):
        original_bytes = self.input_path.read_bytes()

        result = self.run_cli("--input", self.input_path, "--output", self.input_path)

        self.assertEqual(result.returncode, 1)
        self.assertIn("aliases the input", result.stderr)
        self.assertEqual(self.input_path.read_bytes(), original_bytes)

    def test_refuses_hardlink_output_alias_and_preserves_original(self):
        output_path = self.directory / "hardlink.xml"
        os.link(self.input_path, output_path)
        original_bytes = self.input_path.read_bytes()

        result = self.run_cli("--input", self.input_path, "--output", output_path)

        self.assertEqual(result.returncode, 1)
        self.assertIn("aliases the input", result.stderr)
        self.assertEqual(self.input_path.read_bytes(), original_bytes)
        self.assertEqual(output_path.read_bytes(), original_bytes)

    def test_refuses_symlink_output_alias_and_preserves_original(self):
        output_path = self.directory / "symlink.xml"
        output_path.symlink_to(self.input_path)
        original_bytes = self.input_path.read_bytes()

        result = self.run_cli("--input", self.input_path, "--output", output_path)

        self.assertEqual(result.returncode, 1)
        self.assertIn("aliases the input", result.stderr)
        self.assertEqual(self.input_path.read_bytes(), original_bytes)
        self.assertEqual(output_path.read_bytes(), original_bytes)

    def test_refuses_existing_destinations_without_overwriting(self):
        output_path = self.directory / "existing.xml"
        output_path.write_bytes(b"keep output")

        result = self.run_cli("--input", self.input_path, "--output", output_path)

        self.assertEqual(result.returncode, 1)
        self.assertIn("already exists", result.stderr)
        self.assertEqual(output_path.read_bytes(), b"keep output")

    def test_refuses_existing_report_before_creating_output(self):
        output_path = self.directory / "sanitized.xml"
        report_path = self.directory / "existing-report.json"
        report_path.write_text('{"keep": true}', encoding="utf-8")

        result = self.run_cli(
            "--input", self.input_path,
            "--output", output_path,
            "--report", report_path,
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn("report destination already exists", result.stderr)
        self.assertFalse(output_path.exists())
        self.assertEqual(report_path.read_text(encoding="utf-8"), '{"keep": true}')

    def test_refuses_output_and_report_alias_before_writing(self):
        destination = self.directory / "same-destination"

        result = self.run_cli(
            "--input", self.input_path,
            "--output", destination,
            "--report", destination,
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn("destinations alias", result.stderr)
        self.assertFalse(destination.exists())

    def test_invalid_xml_has_safe_error_and_creates_no_output(self):
        self.input_path.write_bytes(b"<opnsense><password>synthetic-secret</opnsense>")
        output_path = self.directory / "sanitized.xml"

        result = self.run_cli("--input", self.input_path, "--output", output_path)

        self.assertEqual(result.returncode, 1)
        self.assertIn("not valid XML", result.stderr)
        self.assertNotIn("synthetic-secret", result.stderr)
        self.assertFalse(output_path.exists())

    def test_unknown_xml_encoding_has_safe_error_and_creates_no_output(self):
        encoding_name = "attacker-controlled-encoding"
        self.input_path.write_bytes(
            f'<?xml version="1.0" encoding="{encoding_name}"?><opnsense/>'.encode("ascii")
        )
        output_path = self.directory / "sanitized.xml"

        result = self.run_cli("--input", self.input_path, "--output", output_path)

        self.assertEqual(result.returncode, 1)
        self.assertIn("Error: input is not valid XML.", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertNotIn(encoding_name, result.stderr)
        self.assertFalse(output_path.exists())

    def test_missing_input_has_nonzero_status_and_creates_no_output(self):
        output_path = self.directory / "sanitized.xml"
        missing_path = self.directory / "missing.xml"

        result = self.run_cli("--input", missing_path, "--output", output_path)

        self.assertEqual(result.returncode, 1)
        self.assertIn("existing regular file", result.stderr)
        self.assertFalse(output_path.exists())


if __name__ == "__main__":
    unittest.main()
