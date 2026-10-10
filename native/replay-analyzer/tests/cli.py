"""Exercise failure paths without requiring or redistributing StarCraft assets."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

binary = str(Path(sys.argv[1]).resolve())
env = {key: value for key, value in os.environ.items() if not key.startswith('OPENBW_')}


def run(args, code, message):
    result = subprocess.run([binary, *args], env=env, capture_output=True, text=True, timeout=20)
    assert result.returncode == code, (args, result.returncode, result.stderr)
    assert message in result.stdout + result.stderr, (args, result.stdout, result.stderr)


run(['--help'], 0, 'usage: sb-replay-analyzer')
run(['--version'], 0, 'sb-replay-analyzer 0.1.0')
run([], 2, 'usage:')
run(['--unknown'], 2, 'unknown or incomplete argument')
with tempfile.TemporaryDirectory(prefix='sb analyzer ') as directory:
    replay = Path(directory) / 'input.rep'
    output = Path(directory) / 'output.ndjson'
    args = ['--replay', str(replay), '--output', str(output)]
    run(args, 2, 'replay file does not exist')
    replay.write_bytes(b'not a real replay')
    run(args, 2, 'OPENBW_MPQ_PATH')
    for interval in ['0', '1441', '-1']:
        run([*args, '--interval-frames', interval], 2, 'interval frames must be between')
    run([*args, '--interval-frames', '24junk'], 2, 'invalid interval frames')
    run(['--replay', str(replay), '--output', str(replay)], 2, 'must not overwrite')
    assert replay.read_bytes() == b'not a real replay'
    assert not output.exists(), 'invalid input created an output artifact'
print('Analyzer CLI tests passed')
