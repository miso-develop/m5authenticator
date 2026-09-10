from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class LocalEnvContractTest(unittest.TestCase):
    def test_template_and_ignore_contract(self) -> None:
        values: dict[str, str] = {}
        for raw_line in (ROOT / ".env.example").read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            key, separator, value = line.partition("=")
            self.assertEqual(separator, "=", line)
            values[key] = value

        self.assertEqual(
            set(values),
            {"M5AUTH_IDF_VERSION", "M5AUTH_CHIP", "M5AUTH_PORT"},
        )
        self.assertTrue(values)
        self.assertTrue(all(value == "" for value in values.values()))

        gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertIn("\n.env\n", f"\n{gitignore}")
        self.assertIn("!.env.example", gitignore)

    def test_windows_loader_is_crlf_and_allowlisted(self) -> None:
        raw = (ROOT / "scripts" / "load-env.cmd").read_bytes()
        self.assertIn(b"\r\n", raw)
        self.assertNotIn(b"\n", raw.replace(b"\r\n", b""))

        text = raw.decode("utf-8")
        for key in ("M5AUTH_IDF_VERSION", "M5AUTH_CHIP", "M5AUTH_PORT"):
            self.assertIn(key, text)
        self.assertIn("v5.5.5", text)
        self.assertIn("esp32s3", text)
        self.assertIn("Unsupported key in .env", text)


if __name__ == "__main__":
    unittest.main()
