import json, subprocess, sys, tempfile, unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/"src"))
from vikunjaoidc.model import CASES, evaluate_case, decode_boolish

class T(unittest.TestCase):
    def test_all(self):
        for c in CASES:
            with self.subTest(c.id):
                self.assertTrue(evaluate_case(c)["ok"], evaluate_case(c))
    def test_pos_flip(self):
        flips = [evaluate_case(c) for c in CASES if c.kind=="pos"]
        self.assertEqual(len(flips), 3)
        for r in flips: self.assertTrue(r["flips"], r)
    def test_oracle(self):
        out = subprocess.check_output([sys.executable, str(ROOT/"scripts"/"derive_expected.py")], text=True)
        by = {c.id:c for c in CASES}
        for ln in out.splitlines():
            if not ln or ln.startswith("id"): continue
            cid, kind, pre, post = ln.split("\t")
            c = by[cid]
            self.assertEqual((pre, post), (c.pre, c.post))
    def test_boolish(self):
        self.assertTrue(decode_boolish(True))
        self.assertTrue(decode_boolish("true"))
        self.assertTrue(decode_boolish("1"))
        self.assertFalse(decode_boolish("false"))
        self.assertFalse(decode_boolish(0))
        self.assertFalse(decode_boolish(None))
    def test_regen(self):
        from vikunjaoidc.cli import _write_results
        with tempfile.TemporaryDirectory() as tmp:
            _write_results(Path(tmp))
            for name in ("cases.csv","summary.csv","SHA256SUMS"):
                self.assertEqual((ROOT/"results"/name).read_bytes(), (Path(tmp)/name).read_bytes())
if __name__ == "__main__":
    unittest.main()
