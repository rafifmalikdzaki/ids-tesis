#!/usr/bin/env python3
"""
Debug script to check map communication
"""

import subprocess
import json

def run_bpftool(args):
    """Run bpftool command and return output"""
    try:
        cmd = ['sudo-rs', 'bpftool'] + args
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        return result.stdout.strip(), result.stderr.strip()
    except Exception as e:
        print(f"Error running bpftool: {e}")
        return "", str(e)

def find_map_id(map_name):
    """Find map ID by name"""
    stdout, stderr = run_bpftool(['map', 'list'])
    print(f"Map list stdout: {stdout[:200]}...")
    print(f"Map list stderr: {stderr}")

    if not stdout:
        return None

    for line in stdout.split('\n'):
        if map_name in line:
            print(f"Found map line: {line}")
            parts = line.split(':')
            if len(parts) > 0:
                try:
                    return int(parts[0])
                except ValueError:
                    continue
    return None

def test_map_dump(map_id):
    """Test dumping a map"""
    stdout, stderr = run_bpftool(['map', 'dump', 'id', str(map_id)])
    print(f"Map dump stdout (first 500 chars): {stdout[:500]}...")
    print(f"Map dump stderr: {stderr}")
    return stdout

if __name__ == '__main__':
    print("=== Debug BPF Map Communication ===")

    # Check if we can find the map
    map_id = find_map_id('bucket_counters')
    print(f"bucket_counters map ID: {map_id}")

    if map_id:
        # Test dumping the map
        dump_output = test_map_dump(map_id)

        # Try to parse it as JSON
        try:
            if dump_output.startswith('['):
                data = json.loads(dump_output)
                print(f"Successfully parsed JSON with {len(data)} entries")
                for entry in data[:2]:  # Show first 2 entries
                    print(f"Entry: {entry}")
            else:
                print("Output is not JSON format")
        except Exception as e:
            print(f"JSON parsing error: {e}")
    else:
        print("Could not find bucket_counters map")

        # List all maps
        stdout, stderr = run_bpftool(['map', 'list'])
        print("All maps:")
        print(stdout)