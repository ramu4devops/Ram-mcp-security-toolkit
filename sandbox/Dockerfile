# Hardened, disposable scanner image for the MCP Security review platform.
# It bundles the REAL review-module scripts. The host runs this image once
# per review with strict flags (--network none, --read-only, --cap-drop ALL,
# non-root, --security-opt no-new-privileges). No submitted repo code is ever
# executed on the host -- only inside a container like this.
FROM node:22-bookworm-slim

# Content revision of the sandbox/ tree, passed by build.sh / review.sh. The
# host compares this label against the current tree so a changed sandbox
# triggers an automatic rebuild instead of a stale-image error.
ARG SANDBOX_REV=dev
LABEL mcp.sandbox_rev=$SANDBOX_REV

RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/tool-poisoning
COPY tool-poisoning/   /opt/tool-poisoning/
COPY rug-pull/         /opt/rug-pull/
COPY resource/         /opt/resource/
COPY secrets/          /opt/secrets/
COPY prompt-injection/ /opt/prompt-injection/
COPY supply-chain/     /opt/supply-chain/
COPY sast/             /opt/sast/
COPY confused-deputy/  /opt/confused-deputy/
COPY audit/            /opt/audit/
COPY shadow/           /opt/shadow/

# The MCP client SDK is installed LOCALLY next to introspect.mjs so ESM
# bare-specifier resolution finds it regardless of the target repo's cwd.
RUN npm install @modelcontextprotocol/sdk@^1 --no-audit --no-fund --loglevel=error \
 && useradd -u 10001 -m scanner \
 && chown -R scanner:scanner \
      /opt/tool-poisoning /opt/rug-pull /opt/resource /opt/secrets \
      /opt/prompt-injection /opt/supply-chain /opt/sast /opt/confused-deputy \
      /opt/audit /opt/shadow

USER scanner
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    NPM_CONFIG_CACHE=/tmp/.npm \
    HOME=/tmp

# Default: run the tool-poisoning orchestrator. The host appends:
#   /work/repo --server-name "<name>" --mode <static|dynamic|auto>
ENTRYPOINT ["python3", "/opt/tool-poisoning/run_tool_poisoning.py"]
