#!/usr/bin/env bash
# Sets up repoward under its own Linux user, as docs/SEPARATE_USER.md describes, then checks from
# an unprivileged agent account that the separation holds. CI runs this on a throwaway machine.
#
# Usage, as root: check_separation.sh path/to/repoward.whl
set -euo pipefail

WHEEL="$1"
AGENT=agent
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok: $*"; }

# 1. The server's user, which owns everything the agent must not reach.
useradd --system --home-dir /var/lib/repoward --create-home --shell /usr/sbin/nologin repoward
chmod 700 /var/lib/repoward

# 2. Install into a directory only root can change.
python3 -m venv /opt/repoward
/opt/repoward/bin/pip install --quiet "$WHEEL"

# 3. The policy and the GitHub token, readable by the server's user only.
sudo -u repoward REPOWARD_HOME=/var/lib/repoward /opt/repoward/bin/repoward init \
  --repo octo-org/example >/dev/null
install -d -m 750 -o root -g repoward /etc/repoward
install -m 640 -o root -g repoward /dev/null /etc/repoward/env
echo "GITHUB_TOKEN=not-a-real-token" >/etc/repoward/env

# 4. A fixed launcher, so the agent cannot choose the command, its arguments or its environment.
cat >/usr/local/bin/repoward-serve <<'EOF'
#!/bin/sh
set -a
. /etc/repoward/env
set +a
export REPOWARD_HOME=/var/lib/repoward
exec /opt/repoward/bin/repoward serve
EOF
chmod 755 /usr/local/bin/repoward-serve

# 5. The agent's account may start that launcher as repoward, with no arguments, and nothing else.
useradd --create-home --shell /bin/bash "$AGENT"
cat >/etc/sudoers.d/repoward <<EOF
$AGENT ALL=(repoward) NOPASSWD: /usr/local/bin/repoward-serve ""
EOF
chmod 440 /etc/sudoers.d/repoward
visudo -cf /etc/sudoers.d/repoward >/dev/null

# The agent gets an MCP client of its own, outside the server's files.
python3 -m venv /opt/agent
/opt/agent/bin/pip install --quiet "$WHEEL"
cat >/tmp/agent_client.py <<'EOF'
import anyio
from mcp import Client, StdioServerParameters

SERVER = StdioServerParameters(
    command="sudo", args=["-n", "-u", "repoward", "/usr/local/bin/repoward-serve"]
)


async def main() -> None:
    async with Client(SERVER) as client:
        result = await client.call_tool("ping", {})
        assert not result.is_error, result


anyio.run(main)
EOF
chmod 644 /tmp/agent_client.py

as_agent() { sudo -u "$AGENT" -H "$@"; }

# The agent can use the tools.
as_agent /opt/agent/bin/python /tmp/agent_client.py || fail "the agent could not use the server"
pass "the agent can call tools"

# It cannot read or change the server's files or token.
for file in /var/lib/repoward/policy.yaml /var/lib/repoward/audit.jsonl \
  /var/lib/repoward/approvals.db /etc/repoward/env; do
  [ -e "$file" ] || fail "$file was not created"
  if as_agent cat "$file" >/dev/null 2>&1; then fail "the agent can read $file"; fi
done
pass "the agent cannot read the policy, audit log, approvals or token"
if as_agent sh -c 'echo x >> /var/lib/repoward/policy.yaml' 2>/dev/null; then
  fail "the agent can edit the policy"
fi
if as_agent sh -c 'echo x > /usr/local/bin/repoward-serve' 2>/dev/null; then
  fail "the agent can change the launcher"
fi
if as_agent sh -c 'touch /opt/repoward/bin/x' 2>/dev/null; then
  fail "the agent can change the installed server"
fi
pass "the agent cannot change the policy, launcher or installation"

# It cannot run anything else as repoward, or change how the launcher runs.
refused() {
  if as_agent sudo -n -u repoward "$@" >/dev/null 2>&1; then fail "the agent ran: $*"; fi
}
refused /opt/repoward/bin/repoward approvals list
refused /opt/repoward/bin/repoward flow reset
refused /usr/local/bin/repoward-serve --http
refused PYTHONPATH=/tmp /usr/local/bin/repoward-serve
refused REPOWARD_HOME=/tmp /usr/local/bin/repoward-serve
refused /bin/sh -c id
pass "the agent cannot approve, reset, add arguments, set variables or run a shell as repoward"

# A person with full sudo can still review and approve.
sudo -u repoward REPOWARD_HOME=/var/lib/repoward /opt/repoward/bin/repoward approvals list \
  >/dev/null || fail "an administrator could not list approvals"
sudo -u repoward /opt/repoward/bin/repoward audit verify /var/lib/repoward/audit.jsonl \
  | grep -q '^OK' || fail "the audit log did not verify"
grep -q '"tool":"ping"' /var/lib/repoward/audit.jsonl || fail "the call was not audited"
pass "an administrator can review approvals and verify the audit log"
echo "Separation holds."
