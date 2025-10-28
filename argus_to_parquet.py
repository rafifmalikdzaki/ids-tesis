#!/usr/bin/env python3
import pyarrow as pa
import pyarrow.parquet as pq
import pyarrow.csv as pv
import subprocess, os, sys, time
import csv
from datetime import datetime
from io import BytesIO

# --- Config ---
BATCH_SIZE = 200
ROTATE_EVERY_MIN = 60
HEARTBEAT_SEC = 10
VERBOSITY = 1  # 0=silent, 1=normal, 2=debug, 3=show each flow
OUTPUT_FORMAT = "parquet"  # "parquet" or "csv"

# --- Schemas (all lowercase) ---
BASIC_SCHEMA = pa.schema([
    ("stime", pa.timestamp("us")),
    ("ltime", pa.timestamp("us")),
    ("saddr", pa.string()),
    ("daddr", pa.string()),
    ("sport", pa.string()),
    ("dport", pa.string()),
    ("proto", pa.string()),
    ("state", pa.string()),
    ("bytes", pa.int64()),
    ("pkts", pa.int64()),
    ("dur", pa.float64()),
])

TCP_SCHEMA = pa.schema([
    ("proto", pa.string()),
    ("state", pa.string()),
    ("retran", pa.int32()),
    ("rtt", pa.float64()),
    ("rttmin", pa.float64()),
    ("rttmax", pa.float64()),
    ("rttstddev", pa.float64()),
    ("win", pa.int64()),
    ("winsize", pa.int64()),
    ("tcpopt", pa.string()),
    ("tcpflags", pa.string()),
    ("ack", pa.int64()),
    ("sack", pa.int64()),
    ("dupack", pa.int64()),
])

RATE_SCHEMA = pa.schema([
    ("rate", pa.float64()),
    ("srate", pa.float64()),
    ("drate", pa.float64()),
    ("bps", pa.float64()),
    ("pps", pa.float64()),
    ("load", pa.float64()),
    ("avgdur", pa.float64()),
    ("meanps", pa.float64()),
    ("maxps", pa.float64()),
    ("minps", pa.float64()),
    ("stddevps", pa.float64()),
    ("stddevb", pa.float64()),
])

LOSS_SCHEMA = pa.schema([
    ("loss", pa.float64()),
    ("ploss", pa.float64()),
    ("jitter", pa.float64()),
    ("sjitter", pa.float64()),
    ("djitter", pa.float64()),
    ("iatmin", pa.float64()),
    ("iatmax", pa.float64()),
    ("iatmean", pa.float64()),
    ("iatstddev", pa.float64()),
])

APP_SCHEMA = pa.schema([
    ("appname", pa.string()),
    ("appbytes", pa.int64()),
    ("apppkts", pa.int64()),
    ("appbps", pa.float64()),
    ("trans", pa.int32()),
    ("retran", pa.int32()),
    ("hostname", pa.string()),
    ("uri", pa.string()),
    ("mime", pa.string()),
    ("httpmethod", pa.string()),
])

BEHAVIORAL_SCHEMA = pa.schema([
    ("entropy", pa.float64()),
    ("burstcount", pa.int32()),
    ("burstsize", pa.float64()),
    ("idletime", pa.float64()),
    ("activitytime", pa.float64()),
    ("flowage", pa.float64()),
    ("meanrate", pa.float64()),
    ("stddevrate", pa.float64()),
    ("skewdur", pa.float64()),
    ("pktlossratio", pa.float64()),
])

TOPOLOGY_SCHEMA = pa.schema([
    ("flowid", pa.string()),
    ("flowkey", pa.string()),
    ("parent", pa.string()),
    ("child", pa.string()),
    ("sensorid", pa.string()),
    ("node", pa.string()),
    ("interface", pa.string()),
    ("vlan", pa.int32()),
    ("mpls", pa.int32()),
])

SCHEMA_GROUPS = {
    "basic": BASIC_SCHEMA,
    "tcp": TCP_SCHEMA,
    "rate": RATE_SCHEMA,
    "loss": LOSS_SCHEMA,
    "app": APP_SCHEMA,
    "behavioral": BEHAVIORAL_SCHEMA,
    "topology": TOPOLOGY_SCHEMA,
}

# --- Core ---
def print_flow(line_data, header):
    """Print a single flow in real-time (verbosity 3+)"""
    if VERBOSITY < 3:
        return
    
    try:
        fields = [f.strip() for f in line_data.split(',')]
        flow_dict = dict(zip(header, fields))
        
        # Map aliases
        saddr = flow_dict.get('srcaddr', flow_dict.get('saddr', 'N/A'))
        daddr = flow_dict.get('dstaddr', flow_dict.get('daddr', 'N/A'))
        sport = flow_dict.get('sport', 'N/A')
        dport = flow_dict.get('dport', 'N/A')
        proto = flow_dict.get('proto', 'N/A')
        bytes_val = flow_dict.get('totbytes', flow_dict.get('bytes', '0'))
        pkts = flow_dict.get('totpkts', flow_dict.get('pkts', '0'))
        state = flow_dict.get('state', 'N/A')
        
        flow_info = f"  🔹 {saddr}:{sport} → {daddr}:{dport} | "
        flow_info += f"proto={proto} | state={state} | bytes={bytes_val} | pkts={pkts}"
        print(flow_info)
    except Exception as e:
        if VERBOSITY >= 2:
            print(f"[WARN] Error printing flow: {e}")

def summarize(table: pa.Table):
    if VERBOSITY >= 1 and "bytes" in table.column_names:
        df = table.to_pandas()
        avg_bytes = df["bytes"].astype(float).mean()
        max_bytes = df["bytes"].astype(float).max()
        print(f"  ↳ {len(df)} flows | avg bytes={avg_bytes:.1f} | max={max_bytes}")

def process_batch(buffer, header, schema):
    """Process a batch of CSV lines into a PyArrow table matching the schema."""
    from datetime import datetime as dt
    
    csv_bytes = ("\n".join(buffer)).encode()
    csv_buf = BytesIO(csv_bytes)
    
    # Parse CSV
    table = pv.read_csv(csv_buf, read_options=pv.ReadOptions(column_names=header))
    
    # Normalize column names to lowercase
    cols_lower = [c.lower() for c in table.column_names]
    table = table.rename_columns(cols_lower)
    
    # Map Argus field aliases to canonical names
    alias_map = {
        "starttime": "stime",
        "lasttime": "ltime",
        "srcaddr": "saddr",
        "dstaddr": "daddr",
        "totbytes": "bytes",
        "totpkts": "pkts"
    }
    
    # Apply aliases
    new_columns = []
    new_names = []
    for col_name in table.column_names:
        canonical_name = alias_map.get(col_name, col_name)
        new_names.append(canonical_name)
        new_columns.append(table.column(col_name))
    
    table = pa.table(dict(zip(new_names, new_columns)))
    
    # Build new table with all schema fields
    columns_dict = {}
    for field in schema:
        field_name = field.name
        if field_name in table.column_names:
            # Column exists - try to cast it
            col = table.column(field_name)
            try:
                # Convert to the target type
                if pa.types.is_timestamp(field.type):
                    # Parse timestamps manually from Argus format (HH:MM:SS.microseconds)
                    if pa.types.is_string(col.type):
                        # Convert string timestamps to microseconds since epoch
                        timestamps = []
                        for val in col.to_pylist():
                            if val and val.strip():
                                try:
                                    # Argus format: HH:MM:SS.microseconds (time only, no date)
                                    # We'll use today's date
                                    today = dt.now().date()
                                    time_parts = val.split(':')
                                    hour = int(time_parts[0])
                                    minute = int(time_parts[1])
                                    sec_parts = time_parts[2].split('.')
                                    second = int(sec_parts[0])
                                    microsecond = int(sec_parts[1]) if len(sec_parts) > 1 else 0
                                    
                                    timestamp = dt.combine(today, dt.min.time()).replace(
                                        hour=hour, minute=minute, second=second, microsecond=microsecond
                                    )
                                    timestamps.append(timestamp)
                                except:
                                    timestamps.append(None)
                            else:
                                timestamps.append(None)
                        col = pa.array(timestamps, type=pa.timestamp('us'))
                    columns_dict[field_name] = col
                else:
                    columns_dict[field_name] = col.cast(field.type, safe=False)
            except Exception as e:
                if VERBOSITY >= 2:
                    print(f"[WARN] Cannot cast {field_name}: {e}, using nulls")
                columns_dict[field_name] = pa.array([None] * len(table), type=field.type)
        else:
            # Column missing - create null array
            columns_dict[field_name] = pa.array([None] * len(table), type=field.type)
    
    # Create table with schema fields in correct order
    result = pa.table(columns_dict, schema=schema)
    return result

def argus_to_parquet(port: int, out_dir: str, schema_keys: list):
    # Merge selected schemas
    schemas = [SCHEMA_GROUPS[k] for k in schema_keys if k in SCHEMA_GROUPS]
    merged_fields = {}
    for sch in schemas:
        for field in sch:
            merged_fields[field.name] = field.type
    schema = pa.schema([(k, v) for k, v in merged_fields.items()])
    fields = list(schema.names)

    print(f"[INFO] Using schemas: {','.join(schema_keys)}")
    print(f"[INFO] Available schemas: {', '.join(SCHEMA_GROUPS.keys())}")
    print(f"[INFO] Using {len(fields)} fields: {', '.join(fields[:10])}...")
    print(f"[INFO] Output format: {OUTPUT_FORMAT.upper()}")
    print(f"[INFO] Verbosity level: {VERBOSITY}")

    fields_str = " ".join(fields)
    cmd = ["ra", "-S", f"localhost:{port}", "-c", ",", "-s"] + fields_str.split()
    if VERBOSITY >= 2:
        print(f"[DEBUG] Command: {' '.join(cmd)}")

    os.makedirs(out_dir, exist_ok=True)
    print(f"[INFO] Starting Argus stream from port {port}")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True, bufsize=1)

    header = None
    buffer = []
    writer = None
    csv_writer = None
    csv_file = None
    total_flows = 0
    file_start = time.time()
    last_heartbeat = time.time()

    try:
        for line in proc.stdout:
            line = line.strip()
            # Skip empty, comment, and non-CSV (version, status) lines
            if not line or line.startswith("#") or "Ra Version" in line or "Argus" in line:
                continue

            # detect header once
            if header is None and "addr" in line.lower():
                header = [h.strip().lower() for h in line.split(",")]
                if VERBOSITY >= 1:
                    print("Detected header:", header[:10], "...")
                if VERBOSITY >= 3:
                    print("\n--- Real-time Flow Display ---")
                continue

            # Print flow in real-time if verbosity 3+
            print_flow(line, header)
            
            buffer.append(line)
            if len(buffer) >= BATCH_SIZE:
                table = process_batch(buffer, header, schema)
                summarize(table)
                total_flows += len(buffer)

                # Rotation logic
                if (writer is None and csv_writer is None) or (ROTATE_EVERY_MIN and (time.time() - file_start) > ROTATE_EVERY_MIN * 60):
                    if writer:
                        writer.close()
                        writer = None
                    if csv_writer:
                        csv_file.close()
                        csv_writer = None
                        csv_file = None
                    
                    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                    
                    if OUTPUT_FORMAT == "csv":
                        out_path = os.path.join(out_dir, f"flows_{port}_{ts}.csv")
                        csv_file = open(out_path, 'w', newline='')
                        csv_writer = csv.writer(csv_file)
                        # Write CSV header
                        csv_writer.writerow(schema.names)
                        print(f"[INFO] ✨ New CSV file: {out_path}")
                    else:  # parquet
                        out_path = os.path.join(out_dir, f"flows_{port}_{ts}.parquet")
                        writer = pq.ParquetWriter(out_path, schema, compression="zstd")
                        print(f"[INFO] ✨ New Parquet file: {out_path}")
                    
                    file_start = time.time()

                # Write data
                if OUTPUT_FORMAT == "csv":
                    df = table.to_pandas()
                    for _, row in df.iterrows():
                        csv_writer.writerow(row.values)
                    csv_file.flush()
                else:  # parquet
                    writer.write_table(table)
                
                if VERBOSITY >= 3:
                    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] ✅ Batch written: {len(buffer)} flows (total={total_flows:,})\n")
                else:
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] ✅ Wrote {len(buffer)} (total={total_flows:,})")
                buffer.clear()
                last_heartbeat = time.time()

            if VERBOSITY >= 1 and (time.time() - last_heartbeat) > HEARTBEAT_SEC:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] ⏳ Waiting... total={total_flows:,}")
                last_heartbeat = time.time()

    except KeyboardInterrupt:
        print("\n[INFO] Interrupted — stopping stream.")
    finally:
        if buffer and header:
            table = process_batch(buffer, header, schema)
            summarize(table)
            
            # Create writer if none exists
            if writer is None and csv_writer is None:
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                if OUTPUT_FORMAT == "csv":
                    out_path = os.path.join(out_dir, f"flows_{port}_{ts}.csv")
                    csv_file = open(out_path, 'w', newline='')
                    csv_writer = csv.writer(csv_file)
                    csv_writer.writerow(schema.names)
                else:
                    out_path = os.path.join(out_dir, f"flows_{port}_{ts}.parquet")
                    writer = pq.ParquetWriter(out_path, schema, compression="zstd")
            
            # Write final batch
            if OUTPUT_FORMAT == "csv":
                df = table.to_pandas()
                for _, row in df.iterrows():
                    csv_writer.writerow(row.values)
            else:
                writer.write_table(table)
            
            total_flows += len(buffer)
            print(f"[{datetime.now().strftime('%H:%M:%S')}] 🧩 Final flush ({len(buffer)})")
        
        if writer:
            writer.close()
        if csv_file:
            csv_file.close()
        proc.terminate()
        print(f"[INFO] Closed writer — total flows processed: {total_flows:,}")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Convert Argus network flow data to Parquet or CSV format",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic usage (Parquet output)
  python argus_to_parquet.py 562 ./output basic
  
  # CSV output with verbose logging
  python argus_to_parquet.py 562 ./output basic,rate,loss --format csv -v 2
  
  # Show each individual flow
  python argus_to_parquet.py 562 ./output basic -v 3
  
  # Silent mode (no output except errors)
  python argus_to_parquet.py 562 ./output basic,tcp,rate -v 0
  
Available schemas:
  basic, tcp, rate, loss, app, behavioral, topology
  
Verbosity levels:
  0 = Silent (no output)
  1 = Normal (summary only)
  2 = Debug (include command details)
  3 = Verbose (show each individual flow)
        """
    )
    
    parser.add_argument('port', type=int, nargs='?', default=562,
                        help='Argus port to connect to (default: 562)')
    parser.add_argument('output_dir', nargs='?', default='.',
                        help='Output directory for flow files (default: current directory)')
    parser.add_argument('schemas', nargs='?', default='basic',
                        help='Comma-separated list of schemas to use (default: basic)')
    parser.add_argument('-f', '--format', choices=['parquet', 'csv'], default='parquet',
                        help='Output format: parquet or csv (default: parquet)')
    parser.add_argument('-v', '--verbosity', type=int, choices=[0, 1, 2, 3], default=1,
                        help='Verbosity level: 0=silent, 1=normal, 2=debug, 3=show flows (default: 1)')
    parser.add_argument('-b', '--batch-size', type=int, default=5000,
                        help='Number of flows per batch (default: 5000)')
    parser.add_argument('-r', '--rotate', type=int, default=60,
                        help='Rotate file every N minutes (default: 60, 0=disable)')
    
    args = parser.parse_args()
    
    # Update global configs
    OUTPUT_FORMAT = args.format
    VERBOSITY = args.verbosity
    BATCH_SIZE = args.batch_size
    ROTATE_EVERY_MIN = args.rotate
    
    schema_keys = args.schemas.split(',')
    
    argus_to_parquet(args.port, args.output_dir, schema_keys)
