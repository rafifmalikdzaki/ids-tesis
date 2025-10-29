#!/usr/bin/env python3
"""
Debug script to test BPF map reading
"""
import subprocess
import json

def find_map_id(map_name):
    """Find map ID"""
    try:
        cmd = ['sudo-rs', 'bpftool', 'map', 'list']
        result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=2)
        stdout = result.stdout.strip()
        
        print(f"=== bpftool map list output ===")
        print(stdout[:500])
        print()
        
        if not stdout:
            print("ERROR: No output from bpftool map list")
            return None
        
        for line in stdout.split('\n'):
            if map_name in line:
                print(f"Found line: {line}")
                parts = line.split(':')
                if len(parts) > 0:
                    try:
                        map_id = int(parts[0])
                        print(f"Extracted map_id: {map_id}")
                        return map_id
                    except ValueError as e:
                        print(f"ValueError: {e}")
                        continue
        
        print(f"ERROR: Map '{map_name}' not found")
        return None
    except Exception as e:
        print(f"ERROR in find_map_id: {e}")
        return None

def read_map_values(map_id):
    """Read map values"""
    if not map_id:
        print("ERROR: map_id is None")
        return {}
    
    try:
        cmd = ['sudo-rs', 'bpftool', 'map', 'dump', 'id', str(map_id), '-j']
        result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=2)
        stdout = result.stdout.strip()
        
        print(f"\n=== bpftool map dump output (first 500 chars) ===")
        print(stdout[:500])
        print()
        
        if not stdout:
            print("ERROR: No output from bpftool map dump")
            return {}
        
        data = json.loads(stdout)
        print(f"Parsed JSON, {len(data)} entries")
        
        values = {}
        
        for i, entry in enumerate(data):
            print(f"\n--- Entry {i} ---")
            print(f"Keys in entry: {entry.keys()}")
            
            if 'formatted' in entry:
                formatted = entry['formatted']
                key = formatted['key']
                cpu_values = formatted['values']
                total_value = sum(cpu_value['value'] for cpu_value in cpu_values)
                values[key] = total_value
                print(f"Key: {key}, Total: {total_value} (from {len(cpu_values)} CPUs)")
            elif 'key' in entry and 'values' in entry:
                # Handle raw hex values
                key = entry['key']
                if isinstance(key, list):
                    key_str = ''.join(key)
                    key = int(key_str, 16)
                
                total_value = 0
                for cpu_value in entry['values']:
                    if isinstance(cpu_value, dict) and 'value' in cpu_value:
                        value = cpu_value['value']
                        if isinstance(value, list):
                            value_str = ''.join(value)
                            total_value += int(value_str, 16)
                        elif isinstance(value, int):
                            total_value += value
                values[key] = total_value
                print(f"Key: {key} (from hex), Total: {total_value}")
        
        print(f"\n=== Final result ===")
        print(f"Values dict: {values}")
        return values
    except json.JSONDecodeError as e:
        print(f"JSON decode error: {e}")
        return {}
    except Exception as e:
        print(f"ERROR in read_map_values: {e}")
        import traceback
        traceback.print_exc()
        return {}

def main():
    print("=== Debug BPF Map Reading ===\n")
    
    map_name = 'bucket_counters'
    print(f"Looking for map: {map_name}\n")
    
    map_id = find_map_id(map_name)
    if not map_id:
        print("\nFailed to find map!")
        return
    
    print(f"\n✓ Found map ID: {map_id}")
    print("\nReading map values...\n")
    
    values = read_map_values(map_id)
    
    if values:
        print("\n✓ SUCCESS! Got values:")
        total = sum(values.values())
        for bucket, count in sorted(values.items()):
            pct = (count / total * 100) if total > 0 else 0
            print(f"  Bucket {bucket}: {count:,} packets ({pct:.1f}%)")
        print(f"\nTotal: {total:,} packets")
    else:
        print("\n✗ FAILED! No values returned")

if __name__ == '__main__':
    main()
