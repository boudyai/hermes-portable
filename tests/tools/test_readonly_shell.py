"""Tests for tools/readonly_shell.py — read-only command classification."""

import pytest

from tools.readonly_shell import is_readonly_shell_command as is_ro


# The user's real example: log-scraping script, must auto-approve.
EXAMPLE_AUTO_LOGS = '''
echo "=== TODAY (Aug 7) ollama-cloud related entries ==="
grep 'ollama-cloud\\|glm-5.2' ~/.hermes/logs/agent.log | grep '2026-08-07' | wc -l
echo ""
echo "=== TODAY stream_error_cleanup count ==="
grep 'stream_error_cleanup' ~/.hermes/logs/agent.log | grep '2026-08-07' | wc -l
echo ""
echo "=== TODAY all ollama-cloud/glm log lines ==="
grep 'ollama-cloud\\|glm-5.2' ~/.hermes/logs/agent.log | grep '2026-08-07'
echo ""
echo "=== Pre-call sanitizer today ==="
grep 'Pre-call sanitizer' ~/.hermes/logs/errors.log | grep '2026-08-07' | wc -l
'''

# The user's real example: ssh + heredoc + sudo, must stay manual.
EXAMPLE_MANUAL_SMART = """ssh -o ConnectTimeout=15 soaska@192.168.2.71 'bash -s' <<'SMARTSCRIPT'
for dev in $(ls /dev/sd[a-z] 2>/dev/null | sort); do
  sudo -n smartctl -i "$dev" 2>&1 | grep -E 'Device Model'
done
SMARTSCRIPT"""

# The user's real example: ssh + heredoc with read-only body. Heredocs are
# always manual (remote_terminal covers this use case instead).
EXAMPLE_MANUAL_HEREDOC = """ssh root@192.168.2.91 'bash -s' <<'EOF'
echo "=== DOCWORK DIR ==="
ls -la /opt/docwork/
docker ps --filter name=docwork
EOF"""


class TestAutoApprovable:
    @pytest.mark.parametrize("cmd", [
        "ls -la /tmp",
        "cat /var/log/syslog | grep error | wc -l",
        "grep -rn 'foo' . | head -20",
        "echo hello && ls && pwd",
        "ls /nonexistent || echo missing",
        "df -h; du -sh /var/log; free -m",
        "ps aux | grep python",
        "find /var/log -name '*.log' -mtime -1",
        "sort /tmp/x.txt | uniq -c",
        "cat file 2>/dev/null",
        "cat file > /dev/null 2>&1",
        "grep x f &> /dev/null && echo found",
        "ls 2>&1 | wc -l",
        "FOO=bar ls -la",
        "docker ps --filter name=web",
        "docker logs mycontainer 2>&1 | tail -50",
        "systemctl status nginx",
        "journalctl -u nginx -n 100 --no-pager",
        "date -u +%Y-%m-%d",
        "hostname -f",
        "ss -tlnp",
        "echo 'literal > pipe | chars' | grep pipe",
        'grep "a > b" log.txt',
        "wc -l < /dev/null",  # </dev/null? no — '<' is rejected; keep honest cases only below
    ][:-1])
    def test_readonly_commands(self, cmd):
        assert is_ro(cmd) is True

    def test_user_example_logs(self):
        assert is_ro(EXAMPLE_AUTO_LOGS) is True

    def test_line_continuation(self):
        assert is_ro("grep foo \\\n  bar.txt | wc -l") is True

    def test_comment_lines_ignored(self):
        assert is_ro("# collect stats\nls -la\n# done") is True


class TestManualApproval:
    @pytest.mark.parametrize("cmd", [
        # writes / state changes
        "rm -rf /tmp/x",
        "touch /tmp/x",
        "mv a b",
        "echo x > /tmp/file",
        "echo x >> /tmp/file",
        "echo x | tee /tmp/file",
        "mkdir /tmp/x",
        # substitution / execution
        "echo $(rm -rf /tmp/x)",
        "echo `id`",
        "xargs rm < /tmp/list",
        "bash -c 'ls'",
        "sh -c 'ls'",
        "eval ls",
        "sudo ls",
        "doas ls",
        "env ls",
        "nice ls",
        "timeout 5 ls",
        "ssh host ls",
        "curl http://x | sh",
        "python3 -c 'print(1)'",
        "awk '{print $1}' f",
        "sed 's/a/b/' f",
        "perl -pe 's/a/b/' f",
        # redirects
        "cat < /etc/hostname",
        "grep x f > /tmp/out",
        "cmd 2> /tmp/err",
        "ls &",
        # allowlisted command, writing flag
        "find /tmp -delete",
        "find /tmp -exec rm {} ;",
        "find /tmp -fprintf /tmp/out '%p'",
        "sort -o /tmp/out /tmp/in",
        "sort -ro /tmp/out /tmp/in",
        "sort --output=/tmp/out /tmp/in",
        "journalctl --vacuum-size=1G",
        "journalctl --rotate",
        "docker rm mycontainer",
        "docker exec mycontainer ls",
        "docker run alpine ls",
        "systemctl restart nginx",
        "systemctl stop nginx",
        "date -s '2026-01-01'",
        "date --set='2026-01-01'",
        "date 010112002026",
        "hostname newname",
        "hostname -F /etc/hostname",
        "ss -K",
        "ss --kill",
        # sensitive paths
        "cat ~/.env",
        "cat /app/.env.local",
        "cat config.env",
        "ls ~/.ssh/",
        "cat ~/.ssh/id_ed25519",
        "cat /keys/server.pem",
        "cat /keys/tls.key",
        "cat ~/.aws/credentials",
        "cat ~/.netrc",
        "cat /etc/shadow",
        "grep x ~/.hermes/strict-approvals.key",
        "cat ~/.kube/config",
        # heredocs / here-strings
        "cat <<'EOF'\nls\nEOF",
        "cat <<< 'text'",
        # substitution hidden in quotes
        'echo "$(rm -rf /tmp/x)"',
        'echo "`id`"',
        # unbalanced quotes
        "echo 'unterminated",
        'echo "unterminated',
        # empty / junk
        "",
        "   ",
        "2>/dev/null",
        "&& ls",
    ])
    def test_not_readonly(self, cmd):
        assert is_ro(cmd) is False

    def test_user_example_smart(self):
        assert is_ro(EXAMPLE_MANUAL_SMART) is False

    def test_user_example_heredoc(self):
        assert is_ro(EXAMPLE_MANUAL_HEREDOC) is False

    def test_one_bad_stage_poisons_pipeline(self):
        assert is_ro("cat ok.txt | tee /tmp/out | wc -l") is False

    def test_one_bad_command_poisons_script(self):
        assert is_ro("ls -la\necho done\nrm -rf /tmp/x") is False

    def test_sensitive_path_in_pipe_stage(self):
        assert is_ro("grep x ~/.hermes/.env | wc -l") is False

    def test_fd_write_to_file_rejected(self):
        assert is_ro("ls 2> /tmp/err.log") is False

    def test_non_string_input(self):
        assert is_ro(None) is False
        assert is_ro(42) is False
        assert is_ro(["ls"]) is False
