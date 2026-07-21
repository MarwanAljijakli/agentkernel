from __future__ import annotations

import json
import shutil

import pytest
from agentkernel.errors import AgentKernelError
from agentkernel.sandbox.docker import DockerSandbox


def _docker_ready() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        result = DockerSandbox(timeout_seconds=5).run_python("print('probe')")
    except AgentKernelError:
        return False
    return result.exit_code == 0


@pytest.mark.integration
@pytest.mark.skipif(not _docker_ready(), reason="Docker Linux engine/image is unavailable")
def test_effective_container_controls_and_denied_network() -> None:
    source = """
import json
import socket

result = {}
try:
    open('/etc/agentkernel-write-test', 'w').write('escape')
except OSError:
    result['root_write_blocked'] = True
else:
    result['root_write_blocked'] = False

try:
    socket.create_connection(('1.1.1.1', 53), timeout=1)
except OSError:
    result['network_blocked'] = True
else:
    result['network_blocked'] = False

result['host_canary_absent'] = not __import__('os').path.exists('/synthetic-home/.ssh/demo_key')
print(json.dumps(result, sort_keys=True))
"""
    execution = DockerSandbox().run_python(source)
    assert execution.exit_code == 0, execution.stderr
    assert execution.controls.all_required
    assert json.loads(execution.stdout) == {
        "host_canary_absent": True,
        "network_blocked": True,
        "root_write_blocked": True,
    }
