# -*- coding: utf-8 -*-
"""CLI 入口的端到端测试（进程内调用 main，覆盖退出码与输出路径）。"""
from __future__ import annotations

import contextlib
import io
import os
import shutil
import tempfile
import unittest
from pathlib import Path

import certdiag.cli as cli

ROOT = Path(__file__).resolve().parent.parent
CMD = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "cmd.exe"


def run(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(argv)
    finally:
        cli.close_worker()
    return code, out.getvalue(), err.getvalue()


def make_unsigned(dirpath: Path) -> Path:
    p = dirpath / "unsigned.exe"
    p.write_bytes(b"MZ" + b"\0" * 64)
    return p


@unittest.skipUnless(CMD.exists(), "需要 Windows 系统文件")
class TestMainSingle(unittest.TestCase):
    def test_valid_file_exit_zero(self):
        code, out, _ = run([str(CMD), "--offline"])
        self.assertEqual(code, 0)
        self.assertIn("分类", out)
        self.assertIn("有效", out)

    def test_missing_path_exit_three(self):
        code, out, err = run([r"Z:\definitely-missing.exe"])
        self.assertEqual(code, 3)
        self.assertIn("没有可处理的文件", out + err)

    def test_unsigned_is_unknown(self):
        d = Path(tempfile.mkdtemp())
        try:
            f = make_unsigned(d)
            code, out, _ = run([str(f), "--offline"])
            self.assertEqual(code, 0)          # 默认 fail-on invalid
            self.assertIn("无法判定", out)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_fail_on_unknown_exit_two(self):
        d = Path(tempfile.mkdtemp())
        try:
            f = make_unsigned(d)
            code, _, _ = run([str(f), "--offline", "--fail-on", "unknown"])
            self.assertEqual(code, 2)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_fail_on_none_exit_zero(self):
        d = Path(tempfile.mkdtemp())
        try:
            f = make_unsigned(d)
            code, _, _ = run([str(f), "--offline", "--fail-on", "none"])
            self.assertEqual(code, 0)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_require_signature_exit_one(self):
        # 需要一个"是 PE、但没有可验证签名"的文件：复制 cmd.exe 再改一个字节
        d = Path(tempfile.mkdtemp())
        try:
            f = d / "stripped.exe"
            data = bytearray(CMD.read_bytes())
            data += b"X"
            f.write_bytes(bytes(data))
            code, _, err = run([str(f), "--offline", "--require-signature"])
            self.assertEqual(code, 1, err)
            self.assertIn("require-signature", err)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_strict_downgrades_unchecked(self):
        code, out, _ = run([str(CMD), "--revoke", "off", "--strict"])
        self.assertEqual(code, 0)
        self.assertIn("无法判定", out)

    def test_trace_goes_to_stderr(self):
        code, _, err = run([str(CMD), "--offline", "--trace"])
        self.assertEqual(code, 0)
        self.assertIn("[trace]", err)
        self.assertIn("归因", err)


@unittest.skipUnless(CMD.exists(), "需要 Windows 系统文件")
class TestMainOutputs(unittest.TestCase):
    def test_json_written(self):
        d = Path(tempfile.mkdtemp())
        try:
            jf = d / "r.json"
            code, out, _ = run([str(CMD), "--offline", "--json", str(jf)])
            self.assertEqual(code, 0)
            self.assertTrue(jf.exists())
            self.assertIn("JSON 报告已写入", out)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_md_written(self):
        d = Path(tempfile.mkdtemp())
        try:
            mf = d / "r.md"
            code, out, _ = run([str(CMD), "--offline", "--md", str(mf)])
            self.assertEqual(code, 0)
            self.assertTrue(mf.exists())
            self.assertIn("Markdown 报告已写入", out)
            self.assertIn("# 证书诊断报告", mf.read_text(encoding="utf-8"))
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_quiet_hides_per_file_lines(self):
        code, out, _ = run([str(CMD), "--offline", "-q"])
        self.assertEqual(code, 0)
        self.assertNotIn("分类：", out)


@unittest.skipUnless(CMD.exists(), "需要 Windows 系统文件")
class TestMainBatch(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        shutil.copy2(CMD, self.dir / "a.exe")
        make_unsigned(self.dir)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_batch_summary(self):
        code, out, _ = run([str(self.dir), "--offline", "-q"])
        self.assertEqual(code, 0)
        self.assertIn("共 2 个文件", out)
        self.assertIn("无法判定", out)

    def test_batch_fail_on_unknown(self):
        code, _, _ = run([str(self.dir), "--offline", "-q", "--fail-on", "unknown"])
        self.assertEqual(code, 2)

    def test_only_filter(self):
        code, out, _ = run([str(self.dir), "--offline", "-q", "--only", "unknown"])
        self.assertEqual(code, 0)
        self.assertIn("筛选后输出 1 个", out)

    def test_only_no_match_is_not_an_error(self):
        code, out, _ = run([str(self.dir), "--offline", "-q", "--only", "invalid"])
        self.assertEqual(code, 0)
        self.assertIn("筛选后输出 0 个", out)


@unittest.skipUnless(CMD.exists(), "需要 Windows 系统文件")
class TestMainArgs(unittest.TestCase):
    def test_version(self):
        out = io.StringIO()
        with self.assertRaises(SystemExit) as cm:
            with contextlib.redirect_stdout(out):
                cli.main(["--version"])
        self.assertEqual(cm.exception.code, 0)
        self.assertIn("certdiag", out.getvalue())

    def test_help_exits_zero(self):
        with self.assertRaises(SystemExit) as cm:
            with contextlib.redirect_stdout(io.StringIO()):
                cli.main(["--help"])
        self.assertEqual(cm.exception.code, 0)

    def test_bad_fail_on(self):
        with self.assertRaises(SystemExit) as cm:
            with contextlib.redirect_stderr(io.StringIO()):
                cli.main(["x", "--fail-on", "nope"])
        self.assertEqual(cm.exception.code, 2)

    def test_no_probe_plus_auto_warns(self):
        code, _, err = run([str(CMD), "--no-probe", "--revoke", "auto"])
        self.assertEqual(code, 0)
        self.assertIn("冲突", err)

