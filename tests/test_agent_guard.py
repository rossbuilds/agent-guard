#!/usr/bin/env python3
"""Tests for agent-guard."""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import agent_guard  # noqa: E402


def decision(cmd: str, cwd=None):
    return agent_guard.decide(cmd, cwd=cwd)


def assert_blocked(testcase: unittest.TestCase, cmd: str):
    r = decision(cmd)
    testcase.assertIsNotNone(r, msg=f"expected block for: {cmd}")
    testcase.assertIn(r[0], {"ask", "deny"}, msg=f"unexpected decision for: {cmd} -> {r}")


class TestRm(unittest.TestCase):
    def test_rm_rf_tmp_ask(self):
        r = decision("rm -rf /tmp/foo")
        self.assertIsNotNone(r)
        self.assertEqual(r[0], "ask")
        self.assertIn("recursive rm", r[1])

    def test_rm_rf_root_deny(self):
        r = decision("rm -rf /")
        self.assertIsNotNone(r)
        self.assertEqual(r[0], "deny")

    def test_rm_rf_home_deny(self):
        r = decision("rm -rf ~")
        self.assertEqual(r[0], "deny")

    def test_rm_rf_home_star_deny(self):
        r = decision("rm -rf ~/*")
        self.assertEqual(r[0], "deny")

    def test_rm_fr(self):
        r = decision("rm -fr /var/tmp/x")
        self.assertIsNotNone(r)
        self.assertEqual(r[0], "ask")

    def test_rm_r_only(self):
        r = decision("rm -r build/")
        self.assertIsNotNone(r)
        self.assertEqual(r[0], "ask")

    def test_sudo_rm_rf(self):
        r = decision("sudo rm -rf /tmp/cache")
        self.assertIsNotNone(r)

    def test_rm_chained_and(self):
        r = decision("echo hi && rm -rf /tmp/x")
        self.assertIsNotNone(r)

    def test_rm_chained_semicolon(self):
        r = decision("cd /tmp; rm -rf stuff")
        self.assertIsNotNone(r)

    def test_rm_piped(self):
        r = decision("true | rm -rf /tmp/x")
        self.assertIsNotNone(r)

    def test_rm_in_cmdsub(self):
        r = decision("echo $(rm -rf /tmp/nested)")
        self.assertIsNotNone(r)

    def test_rm_file_safe(self):
        self.assertIsNone(decision("rm file.txt"))

    def test_rm_f_file_safe(self):
        self.assertIsNone(decision("rm -f file.txt"))

    def test_quoted_rm_rf_safe(self):
        self.assertIsNone(decision('echo "rm -rf /"'))

    def test_single_quoted_rm_safe(self):
        self.assertIsNone(decision("echo 'rm -rf ~'"))


class TestGit(unittest.TestCase):
    def test_force_push(self):
        r = decision("git push --force origin main")
        self.assertIsNotNone(r)
        self.assertEqual(r[0], "ask")

    def test_force_push_short(self):
        r = decision("git push -f")
        self.assertEqual(r[0], "ask")

    def test_force_with_lease_ask(self):
        r = decision("git push --force-with-lease")
        self.assertIsNotNone(r)
        self.assertEqual(r[0], "ask")
        self.assertIn("force-with-lease", r[1])

    def test_normal_push_safe(self):
        self.assertIsNone(decision("git push origin main"))

    def test_reset_hard(self):
        r = decision("git reset --hard HEAD~1")
        self.assertEqual(r[0], "ask")

    def test_clean_fd(self):
        r = decision("git clean -fd")
        self.assertEqual(r[0], "ask")

    def test_clean_df(self):
        r = decision("git clean -df")
        self.assertEqual(r[0], "ask")

    def test_branch_D(self):
        r = decision("git branch -D feature")
        self.assertEqual(r[0], "ask")

    def test_branch_d_safe(self):
        # lowercase -d is soft delete; we only flag -D
        self.assertIsNone(decision("git branch -d feature"))

    def test_checkout_pathspec_ask(self):
        r = decision("git checkout -- src")
        self.assertIsNotNone(r)
        self.assertEqual(r[0], "ask")

    def test_checkout_ref_pathspec_ask(self):
        r = decision("git checkout main -- src")
        self.assertIsNotNone(r)
        self.assertEqual(r[0], "ask")

    def test_restore_worktree_pathspec_ask(self):
        r = decision("git restore src")
        self.assertIsNotNone(r)
        self.assertEqual(r[0], "ask")

    def test_restore_staged_only_safe(self):
        self.assertIsNone(decision("git restore --staged a.txt"))

    def test_switch_safe(self):
        self.assertIsNone(decision("git switch main"))


class TestSql(unittest.TestCase):
    def test_drop_database_deny(self):
        r = decision("DROP DATABASE prod")
        self.assertEqual(r[0], "deny")

    def test_drop_table_ask(self):
        r = decision("DROP TABLE users")
        self.assertEqual(r[0], "ask")

    def test_truncate_ask(self):
        r = decision("TRUNCATE TABLE logs")
        self.assertEqual(r[0], "ask")

    def test_delete_no_where(self):
        r = decision("DELETE FROM users")
        self.assertEqual(r[0], "ask")

    def test_delete_with_where_safe(self):
        self.assertIsNone(decision("DELETE FROM t WHERE id=1"))

    def test_psql_drop_quoted(self):
        r = decision('psql -c "DROP DATABASE foo"')
        self.assertIsNotNone(r)
        self.assertEqual(r[0], "deny")
        self.assertIn("DROP DATABASE", r[1])

    def test_psql_delete_quoted(self):
        r = decision('psql -c "DELETE FROM users"')
        self.assertIsNotNone(r)
        self.assertEqual(r[0], "ask")
        self.assertIn("DELETE FROM without WHERE", r[1])

    def test_psql_drop_unquoted(self):
        r = decision("psql -c DROP DATABASE foo")
        self.assertEqual(r[0], "deny")

    def test_mysql_drop_database_quoted(self):
        r = decision('mysql -e "DROP DATABASE prod"')
        self.assertIsNotNone(r)
        self.assertEqual(r[0], "deny")
        self.assertIn("DROP DATABASE", r[1])

    def test_mysql_delete_unquoted(self):
        r = decision("mysql -e DELETE FROM t")
        self.assertEqual(r[0], "ask")

    def test_sqlite3_drop_table_quoted(self):
        r = decision('sqlite3 app.db "DROP TABLE x"')
        self.assertIsNotNone(r)
        self.assertEqual(r[0], "ask")
        self.assertIn("DROP TABLE", r[1])

    def test_sqlite3_delete_quoted(self):
        r = decision("sqlite3 app.db 'DELETE FROM users'")
        self.assertIsNotNone(r)
        self.assertEqual(r[0], "ask")
        self.assertIn("DELETE FROM without WHERE", r[1])

    def test_echo_sql_quoted_safe(self):
        self.assertIsNone(decision('echo "DROP DATABASE prod"'))
        self.assertIsNone(decision("echo 'DELETE FROM users'"))


class TestShellC(unittest.TestCase):
    def test_bash_c_rm_rf_root_deny(self):
        r = decision('bash -c "rm -rf /"')
        self.assertIsNotNone(r)
        self.assertEqual(r[0], "deny")
        self.assertIn("recursive rm", r[1])

    def test_sh_c_rm_rf_ask(self):
        r = decision("sh -c 'rm -rf /tmp/x'")
        self.assertIsNotNone(r)
        self.assertEqual(r[0], "ask")
        self.assertIn("recursive rm", r[1])

    def test_bash_lc_rm_rf(self):
        r = decision('bash -lc "rm -rf /var/tmp/cache"')
        self.assertIsNotNone(r)
        self.assertEqual(r[0], "ask")

    def test_bash_c_nested_psql(self):
        r = decision("""bash -c 'psql -c "DROP DATABASE prod"'""")
        self.assertIsNotNone(r)
        self.assertEqual(r[0], "deny")

    def test_echo_rm_rf_still_safe(self):
        self.assertIsNone(decision('echo "rm -rf /"'))
        self.assertIsNone(decision("echo 'rm -rf ~'"))

    def test_bash_c_echo_rm_safe(self):
        self.assertIsNone(decision('bash -c "echo \\"rm -rf /\\""'))


class TestBypassRegression(unittest.TestCase):
    def test_all_previous_bypass_commands_now_block(self):
        bypass_commands = [
            "rm --recursive --force ~",
            "echo cm0gLXJmIC8= | base64 -d | sh",
            'python3 -c "import shutil;shutil.rmtree(\\"/\\")"',
            'perl -e \'system("rm -rf /")\'',
            'node -e "require(\\"fs\\").rmSync(\\"/\\",{recursive:true,force:true})"',
            "git push origin +main",
            "> important.db",
            ": > file",
            "cat /dev/null > file",
            "/bin/rm -rf /",
            "\\rm -rf /",
            'eval "rm -rf /"',
            "RM=rm; $RM -rf /",
            "mv ~ /dev/null",
            "shred important.db",
            "git checkout -- .",
            "git restore .",
            "git stash drop",
            "git filter-branch -- --all",
            "aws s3 rm --recursive s3://b",
            "UPDATE users SET x=1",
            "redis-cli FLUSHALL",
            "docker volume rm data",
            """python3 - <<'PY'
import os
os.system("rm -rf /")
PY""",
        ]
        for cmd in bypass_commands:
            with self.subTest(cmd=cmd):
                assert_blocked(self, cmd)

    def test_additional_requested_risky_forms(self):
        risky = [
            "git stash clear",
            "git filter-repo --force",
            "aws s3 rb --force s3://bucket",
            "redis-cli FLUSHDB",
            "docker volume prune -f",
            'ruby -e \'system("rm -rf /")\'',
            'python3 -c "import os; os.remove(\\"/tmp/file\\")"',
            'node -e "require(\\"fs\\").unlinkSync(\\"/tmp/file\\")"',
        ]
        for cmd in risky:
            with self.subTest(cmd=cmd):
                assert_blocked(self, cmd)


class TestUserReportedRegressions(unittest.TestCase):
    def test_reported_bypasses_are_blocked(self):
        bypasses = [
            "perl -e 'unlink \"/tmp/file\"'",
            "xargs rm -rf <<< \"/tmp/a\"",
            "nice -n 10 rm -rf /",
            "timeout 5 rm -rf /",
            "time rm -rf /",
            "watch rm -rf /tmp/cache",
            "f(){ rm -rf /; }; f",
            "$(printf '%s' rm) -rf /",
            "`printf rm` -rf /",
            "r${IFS}m -rf /",
            'r"m" -rf /',
            "printf 'rm -rf /\\n' | sh",
            'ruby -e \'system("shred -u secret.txt")\'',
            "xargs rm -rf",
            'ruby -e \'FileUtils.rm_rf("/")\'',
            'alias zap="rm -rf"; zap /tmp/x',
        ]
        for cmd in bypasses:
            with self.subTest(cmd=cmd):
                assert_blocked(self, cmd)

    def test_reported_benign_commands_stay_allowed(self):
        benign = [
            "ls -la",
            "cat README.md",
            'echo "rm -rf /"',
            "git push",
            "git push origin main",
            "git status",
            "git checkout main",
            "git checkout -b feat",
            "git switch main",
            "git restore --staged a.txt",
            "npm test",
            "rm file.txt",
            "mv a b",
            "grep -r foo .",
            'python3 -c "print(1)"',
            'node -e "console.log(1)"',
            "npm test > out.log",
            "make 2>&1",
            "ls >/dev/null",
            "docker ps",
            "kubectl get pods",
            'psql -c "SELECT * FROM t"',
            "git log --oneline | head",
            "pytest -q 2>&1 | tee test.log",
            "time npm test",
            "timeout 60 pytest",
            "nice make",
            "xargs -n1 echo",
            "find . -name '*.py'",
            "echo $(date)",
            "ls $HOME",
            "cd $(git rev-parse --show-toplevel)",
            "export PATH=$PATH:/x",
            "watch kubectl get pods",
        ]
        for cmd in benign:
            with self.subTest(cmd=cmd):
                self.assertIsNone(decision(cmd), msg=f"expected allow for: {cmd}")


class TestInfra(unittest.TestCase):
    def test_terraform_destroy(self):
        self.assertEqual(decision("terraform destroy -auto-approve")[0], "ask")

    def test_kubectl_delete(self):
        self.assertEqual(decision("kubectl delete pod x")[0], "ask")

    def test_helm_uninstall(self):
        self.assertEqual(decision("helm uninstall myapp")[0], "ask")

    def test_docker_prune(self):
        self.assertEqual(decision("docker system prune -af")[0], "ask")

    def test_chmod_777_root(self):
        self.assertEqual(decision("chmod -R 777 /")[0], "ask")

    def test_mkfs_deny(self):
        self.assertEqual(decision("mkfs.ext4 /dev/sdb1")[0], "deny")

    def test_dd_dev_deny(self):
        self.assertEqual(decision("dd if=/dev/zero of=/dev/sda bs=1M")[0], "deny")

    def test_find_delete(self):
        self.assertEqual(decision("find /tmp -name '*.log' -delete")[0], "ask")

    def test_safe_echo(self):
        self.assertIsNone(decision("echo hello world"))

    def test_safe_ls(self):
        self.assertIsNone(decision("ls -la /tmp"))


class TestBenignAllowlist(unittest.TestCase):
    def test_user_listed_benign_commands_stay_allowed(self):
        benign = [
            "ls",
            "cat file",
            'echo "rm -rf /"',
            "git push",
            "git push origin main",
            "git status",
            "git checkout main",
            "git checkout -b x",
            "git switch main",
            "git restore --staged file",
            "npm test",
            "rm file.txt",
            "mv a b",
            "grep -r foo .",
            'python3 -c "print(1)"',
            'node -e "console.log(1)"',
            "echo hi > out.log",
            "echo hi >/dev/null 2>&1",
            "docker ps",
            "kubectl get pods",
            "SELECT * FROM t",
            "DELETE FROM t WHERE id=1",
            "UPDATE t SET x=1 WHERE id=2",
        ]
        for cmd in benign:
            with self.subTest(cmd=cmd):
                self.assertIsNone(decision(cmd), msg=f"expected allow for: {cmd}")


class TestConfig(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_allow_wins(self):
        cfg_dir = Path(self.tmp) / ".config" / "agent-guard"
        cfg_dir.mkdir(parents=True)
        (cfg_dir / "config.json").write_text(
            json.dumps({"allow": [r"rm -rf /tmp/allowed"]}), encoding="utf-8"
        )
        with mock.patch.dict(os.environ, {"HOME": self.tmp}, clear=False):
            # Also ensure no local config
            r = decision("rm -rf /tmp/allowed", cwd=self.tmp)
            self.assertIsNone(r)

    def test_deny_override(self):
        local = Path(self.tmp) / ".agent-guard.json"
        local.write_text(json.dumps({"deny": [r"echo dangerous"]}), encoding="utf-8")
        with mock.patch.dict(os.environ, {"HOME": self.tmp}, clear=False):
            r = decision("echo dangerous", cwd=self.tmp)
            self.assertIsNotNone(r)
            self.assertEqual(r[0], "deny")

    def test_ask_rule(self):
        local = Path(self.tmp) / ".agent-guard.json"
        local.write_text(json.dumps({"ask": [r"npm publish"]}), encoding="utf-8")
        with mock.patch.dict(os.environ, {"HOME": self.tmp}, clear=False):
            r = decision("npm publish", cwd=self.tmp)
            self.assertEqual(r[0], "ask")

    def test_mode_deny(self):
        local = Path(self.tmp) / ".agent-guard.json"
        local.write_text(json.dumps({"mode": "deny"}), encoding="utf-8")
        with mock.patch.dict(os.environ, {"HOME": self.tmp}, clear=False):
            r = decision("rm -rf /tmp/x", cwd=self.tmp)
            self.assertEqual(r[0], "deny")

    def test_disable_env(self):
        with mock.patch.dict(os.environ, {"AGENT_GUARD_DISABLE": "1"}):
            self.assertIsNone(decision("rm -rf /"))


class TestHookIo(unittest.TestCase):
    def test_hook_json_deny(self):
        payload = json.dumps(
            {
                "tool_name": "Bash",
                "tool_input": {"command": "rm -rf /"},
                "cwd": "/tmp",
            }
        )
        proc = subprocess.run(
            [sys.executable, str(ROOT / "agent_guard.py")],
            input=payload,
            capture_output=True,
            text=True,
            env={**os.environ, "AGENT_GUARD_DISABLE": "0"},
        )
        self.assertEqual(proc.returncode, 0)
        out = json.loads(proc.stdout)
        self.assertEqual(
            out["hookSpecificOutput"]["permissionDecision"], "deny"
        )
        self.assertEqual(
            out["hookSpecificOutput"]["hookEventName"], "PreToolUse"
        )

    def test_hook_safe_no_output(self):
        payload = json.dumps(
            {
                "tool_name": "Bash",
                "tool_input": {"command": "echo ok"},
                "cwd": "/tmp",
            }
        )
        proc = subprocess.run(
            [sys.executable, str(ROOT / "agent_guard.py")],
            input=payload,
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout.strip(), "")

    def test_cli_check(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "agent_guard.py"), "check", "rm -rf /tmp/x"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertTrue(proc.stdout.startswith("ask:"))

    def test_cli_check_allow(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "agent_guard.py"), "check", "echo hi"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout.strip(), "allow")

    def test_codex_mode(self):
        proc = subprocess.run(
            [
                sys.executable,
                str(ROOT / "agent_guard.py"),
                "check",
                "--codex",
                "mkfs /dev/sdb",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertIn("agent-guard:", proc.stderr)

    def test_malformed_json_fails_safe_to_ask(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "agent_guard.py")],
            input="{bad json",
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0)
        out = json.loads(proc.stdout)
        self.assertEqual(
            out["hookSpecificOutput"]["permissionDecision"], "ask"
        )
        self.assertIn("malformed hook payload", out["hookSpecificOutput"]["permissionDecisionReason"])

    def test_wrong_shape_fails_safe_to_ask(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "agent_guard.py")],
            input='["not-a-dict"]',
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0)
        out = json.loads(proc.stdout)
        self.assertEqual(
            out["hookSpecificOutput"]["permissionDecision"], "ask"
        )

    def test_wrong_tool_input_shape_fails_safe_to_ask(self):
        payload = json.dumps({"tool_name": "Bash", "tool_input": "rm -rf /"})
        proc = subprocess.run(
            [sys.executable, str(ROOT / "agent_guard.py")],
            input=payload,
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0)
        out = json.loads(proc.stdout)
        self.assertEqual(
            out["hookSpecificOutput"]["permissionDecision"], "ask"
        )

    def test_codex_malformed_json_exit_2(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "agent_guard.py"), "--codex"],
            input="{bad json",
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertIn("malformed hook payload", proc.stderr)

    def test_codex_wrong_shape_exit_2(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "agent_guard.py"), "--codex"],
            input='["bad"]',
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertIn("malformed hook payload", proc.stderr)

    def test_codex_wrong_tool_input_shape_exit_2(self):
        payload = json.dumps({"tool_name": "Bash", "tool_input": "rm -rf /"})
        proc = subprocess.run(
            [sys.executable, str(ROOT / "agent_guard.py"), "--codex"],
            input=payload,
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertIn("malformed hook payload", proc.stderr)


def _load_opus_corpus() -> tuple[list[str], list[str]]:
    path = Path("/tmp/opus_corpus.json")
    if not path.is_file():
        raise unittest.SkipTest(f"{path} not found")
    data = json.loads(path.read_text(encoding="utf-8"))
    good: list[str] = []
    for cmd in data.get("good", []):
        if "Makefile" in cmd and "\\techo" in cmd:
            cmd = cmd.replace("\\techo", "\techo")
        good.append(cmd)
    return list(data.get("bad", [])), good


class TestOpusCorpusRegression(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            cls.bad, cls.good = _load_opus_corpus()
        except unittest.SkipTest:
            raise
        cls.empty_cwd = tempfile.mkdtemp()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.empty_cwd, ignore_errors=True)

    def test_opus_bad_commands_blocked(self):
        for cmd in self.bad:
            with self.subTest(cmd=cmd[:80]):
                assert_blocked(self, cmd)

    def test_opus_good_commands_allowed_in_empty_cwd(self):
        for cmd in self.good:
            with self.subTest(cmd=cmd[:80]):
                self.assertIsNone(
                    decision(cmd, cwd=self.empty_cwd),
                    msg=f"expected allow for: {cmd}",
                )


class TestGuardLimits(unittest.TestCase):
    def test_command_over_64kb_defaults_to_ask(self):
        huge = "echo " + ("x" * (agent_guard.MAX_COMMAND_BYTES + 1))
        r = decision(huge)
        self.assertIsNotNone(r)
        self.assertEqual(r[0], "ask")
        self.assertIn("64 KB", r[1])

    def test_eleven_nested_sh_c_ask_or_deny(self):
        import shlex

        inner = "rm -rf /"
        for _ in range(11):
            inner = "sh -c " + shlex.quote(inner)
        r = decision(inner)
        self.assertIsNotNone(r)
        self.assertIn(r[0], {"ask", "deny"})


class TestInstall(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_install_idempotent(self):
        env = {**os.environ, "HOME": self.tmp}
        script = ROOT / "install.sh"
        # First install
        r1 = subprocess.run(
            ["bash", str(script)],
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(r1.returncode, 0, r1.stderr)
        hook = Path(self.tmp) / ".claude" / "hooks" / "agent-guard" / "agent_guard.py"
        self.assertTrue(hook.is_file())
        settings = Path(self.tmp) / ".claude" / "settings.json"
        self.assertTrue(settings.is_file())
        data1 = json.loads(settings.read_text(encoding="utf-8"))
        ptu1 = data1["hooks"]["PreToolUse"]
        # Count our hooks
        def count_ours(data):
            n = 0
            for e in data["hooks"]["PreToolUse"]:
                for h in e.get("hooks", []):
                    args = h.get("args") or []
                    if any("agent_guard.py" in str(a) for a in args):
                        n += 1
            return n

        self.assertEqual(count_ours(data1), 1)

        # Second install — idempotent
        r2 = subprocess.run(
            ["bash", str(script)],
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(r2.returncode, 0, r2.stderr)
        data2 = json.loads(settings.read_text(encoding="utf-8"))
        self.assertEqual(count_ours(data2), 1)

        # Uninstall
        r3 = subprocess.run(
            ["bash", str(script), "--uninstall"],
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(r3.returncode, 0, r3.stderr)
        self.assertFalse(hook.exists())

    def test_install_creates_timestamped_backups_without_overwrite(self):
        env = {**os.environ, "HOME": self.tmp}
        script = ROOT / "install.sh"
        settings_dir = Path(self.tmp) / ".claude"
        settings_dir.mkdir(parents=True, exist_ok=True)
        settings = settings_dir / "settings.json"
        settings.write_text("{}", encoding="utf-8")

        r1 = subprocess.run(
            ["bash", str(script)],
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(r1.returncode, 0, r1.stderr)

        r2 = subprocess.run(
            ["bash", str(script)],
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(r2.returncode, 0, r2.stderr)

        backups = list(settings_dir.glob("settings.json.bak.agent-guard.*"))
        self.assertGreaterEqual(len(backups), 2)
        self.assertEqual(len({b.name for b in backups}), len(backups))

    def test_install_uses_local_checksum_file(self):
        env = {**os.environ, "HOME": self.tmp}
        script = ROOT / "install.sh"
        proc = subprocess.run(
            ["bash", str(script)],
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_install_script_hardening_markers(self):
        text = (ROOT / "install.sh").read_text(encoding="utf-8")
        self.assertIn("set -euo pipefail", text)
        self.assertNotRegex(text, r"\bsudo\b")
        self.assertIn('"timeout": timeout', text)
        self.assertIn('"onFailure": "block"', text)
        self.assertIn("trap cleanup EXIT", text)
        self.assertIn("make_tmp", text)
        self.assertIn('mv -f -- "${tmp_hook}" "${HOOK_SCRIPT}"', text)

    def test_install_hook_entry_timeout_and_on_failure(self):
        env = {**os.environ, "HOME": self.tmp}
        script = ROOT / "install.sh"
        proc = subprocess.run(
            ["bash", str(script)],
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        hook_path = str(
            (Path(self.tmp) / ".claude" / "hooks" / "agent-guard" / "agent_guard.py").resolve()
        )
        settings = json.loads(
            (Path(self.tmp) / ".claude" / "settings.json").read_text(encoding="utf-8")
        )
        ours = None
        for entry in settings["hooks"]["PreToolUse"]:
            for h in entry.get("hooks", []):
                if h.get("args") == [hook_path]:
                    ours = h
        self.assertIsNotNone(ours)
        self.assertEqual(ours["timeout"], 10)
        self.assertEqual(ours["onFailure"], "block")

    def test_install_aborts_on_malformed_settings_without_write(self):
        env = {**os.environ, "HOME": self.tmp}
        script = ROOT / "install.sh"
        settings_dir = Path(self.tmp) / ".claude"
        settings_dir.mkdir(parents=True, exist_ok=True)
        settings = settings_dir / "settings.json"
        bad = "{not valid json"
        settings.write_text(bad, encoding="utf-8")
        before = bad
        proc = subprocess.run(
            ["bash", str(script)],
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertNotEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(settings.read_text(encoding="utf-8"), before)
        hook = settings_dir / "hooks" / "agent-guard" / "agent_guard.py"
        self.assertFalse(hook.exists())

    def test_install_preserves_settings_permissions(self):
        env = {**os.environ, "HOME": self.tmp}
        script = ROOT / "install.sh"
        settings_dir = Path(self.tmp) / ".claude"
        settings_dir.mkdir(parents=True, exist_ok=True)
        settings = settings_dir / "settings.json"
        settings.write_text("{}", encoding="utf-8")
        os.chmod(settings, 0o600)
        proc = subprocess.run(
            ["bash", str(script)],
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        mode = stat.S_IMODE(os.stat(settings).st_mode)
        self.assertEqual(mode, 0o600)

    def test_is_ours_matches_exact_hook_path_only(self):
        env = {**os.environ, "HOME": self.tmp}
        script = ROOT / "install.sh"
        proc = subprocess.run(
            ["bash", str(script)],
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        settings_path = Path(self.tmp) / ".claude" / "settings.json"
        data = json.loads(settings_path.read_text(encoding="utf-8"))
        decoy = "/tmp/decoy-agent-guard/agent_guard.py"
        ptu = data["hooks"]["PreToolUse"]
        ptu[0]["hooks"].append(
            {
                "type": "command",
                "command": "python3",
                "args": [decoy],
                "timeout": 5,
            }
        )
        settings_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        proc2 = subprocess.run(
            ["bash", str(script), "--uninstall"],
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(proc2.returncode, 0, proc2.stderr)
        after = json.loads(settings_path.read_text(encoding="utf-8"))
        decoys = [
            h
            for e in after.get("hooks", {}).get("PreToolUse", [])
            for h in e.get("hooks", [])
            if h.get("args") == [decoy]
        ]
        self.assertEqual(len(decoys), 1)

    def test_missing_sha256sums_fails_install(self):
        env = {**os.environ, "HOME": self.tmp}
        with tempfile.TemporaryDirectory() as fake_repo:
            fake = Path(fake_repo)
            shutil.copy(ROOT / "agent_guard.py", fake / "agent_guard.py")
            shutil.copy(ROOT / "install.sh", fake / "install.sh")
            proc = subprocess.run(
                ["bash", str(fake / "install.sh")],
                capture_output=True,
                text=True,
                env=env,
                cwd=str(fake),
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("SHA256SUMS", proc.stderr)

    def test_skip_verify_allows_missing_sha256sums_with_warning(self):
        env = {
            **os.environ,
            "HOME": self.tmp,
            "AGENT_GUARD_SKIP_VERIFY": "1",
        }
        with tempfile.TemporaryDirectory() as fake_repo:
            fake = Path(fake_repo)
            shutil.copy(ROOT / "agent_guard.py", fake / "agent_guard.py")
            shutil.copy(ROOT / "install.sh", fake / "install.sh")
            proc = subprocess.run(
                ["bash", str(fake / "install.sh")],
                capture_output=True,
                text=True,
                env=env,
                cwd=str(fake),
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("AGENT_GUARD_SKIP_VERIFY", proc.stderr)
            self.assertIn("WARNING", proc.stderr)


class TestAutoReviewRound(unittest.TestCase):
    BLOCK = [
        "find /etc -type f -exec rm -f {} \\;",
        "pkexec rm -rf /var/lib/app",
        "nsenter -t 1 -m -- rm -rf /var/lib/app",
        "systemd-run rm -rf /var/lib/app",
        "firejail --noprofile rm -rf /var/lib/app",
        "unshare -m rm -rf /var/lib/app",
        "prlimit --as=unlimited rm -rf /var/lib/app",
        "k3s kubectl delete ns production",
        "oc delete project production",
        "kubectl drain node1 --force --ignore-daemonsets",
        "kubectl replace --force -f wipe.yaml",
        "terragrunt destroy -auto-approve",
        "pulumi destroy -y",
        "cdk destroy --force",
        "dropdb production",
        "mysqladmin drop production -f",
        "clickhouse-client -q 'DROP DATABASE production'",
        "az group delete -n prod-rg -y",
        "zfs destroy -r tank/production",
        "zpool destroy tank",
        "nvme format /dev/nvme0n1",
        "openssl rand -out /dev/sda 16M",
    ]
    SAFE = [
        "kubectl get pods",
        "pulumi up",
        "terragrunt plan",
        "az group list",
        "zfs list",
        "nvme list",
        "openssl rand -out key.bin 32",
        "find . -name '*.py' -exec grep -l foo {} +",
        "oc get pods",
        "mysqladmin status",
    ]

    def test_block(self):
        for c in self.BLOCK:
            with self.subTest(c=c):
                assert_blocked(self, c)

    def test_safe(self):
        for c in self.SAFE:
            with self.subTest(c=c):
                self.assertIsNone(decision(c), msg=c)


if __name__ == "__main__":
    unittest.main()
