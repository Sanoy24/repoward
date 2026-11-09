# Running repoward as its own user

repoward's rules only hold if the agent cannot reach what the server uses: the GitHub token, the
policy, the approvals database, the flow guard state and the audit log. An agent with a shell under
your own account can reach all of them. This guide puts them under a separate Linux user, and gives
the agent's account permission to start the server and nothing else.

Every step below is checked automatically on a fresh Ubuntu machine by
[scripts/check_separation.sh](https://github.com/Sanoy24/repoward/blob/main/scripts/check_separation.sh).
It confirms that an agent account can call tools but cannot read the files, change them, approve
requests or run anything else as the server's user.

## Setup

Run these as root. Replace `agent` with the account your agent runs as, and `your-org/your-repo`
with your repositories.

1. Create the server's user. Its home directory holds repoward's files, and only it can open them:

   ```bash
   useradd --system --home-dir /var/lib/repoward --create-home --shell /usr/sbin/nologin repoward
   chmod 700 /var/lib/repoward
   ```

2. Install repoward where only root can change it:

   ```bash
   python3 -m venv /opt/repoward
   /opt/repoward/bin/pip install repoward
   ```

3. Create the policy, and store the GitHub token where only the server's user can read it:

   ```bash
   sudo -u repoward REPOWARD_HOME=/var/lib/repoward /opt/repoward/bin/repoward init \
     --repo your-org/your-repo
   install -d -m 750 -o root -g repoward /etc/repoward
   install -m 640 -o root -g repoward /dev/null /etc/repoward/env
   echo "GITHUB_TOKEN=<your-token>" > /etc/repoward/env
   ```

4. Create a fixed launcher. The agent cannot choose its arguments or environment:

   ```bash
   cat > /usr/local/bin/repoward-serve <<'EOF'
   #!/bin/sh
   set -a
   . /etc/repoward/env
   set +a
   export REPOWARD_HOME=/var/lib/repoward
   exec /opt/repoward/bin/repoward serve
   EOF
   chmod 755 /usr/local/bin/repoward-serve
   ```

5. Let the agent's account start that launcher as `repoward`, with no arguments. The `""` at the end
   is what forbids arguments:

   ```bash
   echo 'agent ALL=(repoward) NOPASSWD: /usr/local/bin/repoward-serve ""' > /etc/sudoers.d/repoward
   chmod 440 /etc/sudoers.d/repoward
   visudo -cf /etc/sudoers.d/repoward
   ```

6. In the agent's MCP client, run the server through `sudo`:

   ```json
   {
     "mcpServers": {
       "repoward": {
         "command": "sudo",
         "args": ["-n", "-u", "repoward", "/usr/local/bin/repoward-serve"]
       }
     }
   }
   ```

   The audit log then shows calls as `local:repoward`, the server's user.

## Approving and reviewing

Run the command line tools as the server's user, from an account that has full `sudo` and is not the
agent's:

```bash
sudo -u repoward REPOWARD_HOME=/var/lib/repoward /opt/repoward/bin/repoward approvals list
sudo -u repoward REPOWARD_HOME=/var/lib/repoward /opt/repoward/bin/repoward approvals approve <id>
sudo -u repoward REPOWARD_HOME=/var/lib/repoward /opt/repoward/bin/repoward audit verify
```

## What this does not cover

- **Your own account:** if the agent runs as you and you have `sudo`, it can use `sudo` too. Run the
  agent under its own account, as in step 5. If it must run as you, make `sudo` ask for a password
  every time, so a recent password entry cannot be reused:
  `Defaults timestamp_timeout=0` in a file under `/etc/sudoers.d/`.
- **Docker:** a container alone is not a boundary from an agent that can run `docker`, because it
  could use `docker exec` or mount the container's volume. It only helps when the agent cannot
  use Docker at all.
- **Windows:** an MCP client cannot easily start a server as another Windows user. Run the server in
  WSL using this guide, or on another machine in [HTTP mode](https://github.com/Sanoy24/repoward#serving-over-http),
  where the agent only ever holds its own login token.
- **macOS:** the same approach should work with `dscl` instead of `useradd`, but it has not been
  tested.
- **Other routes out:** the agent's other tools, such as a browser or other MCP servers, are not
  covered. GitHub-side protections, such as a ruleset on your default branch, still matter.
