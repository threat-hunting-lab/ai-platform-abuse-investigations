#!/usr/bin/env python3
"""
CASE-0004: K8s Resource Hijacking Synthetic Data Generator

Generates synthetic Kubernetes telemetry demonstrating:
- API token abuse (from compromised credentials)
- Unauthorized pod creation
- Cryptomining resource abuse
- Network egress to mining pools
"""

import argparse
import random
import yaml
from datetime import datetime, timedelta
from pathlib import Path
import pandas as pd
import numpy as np

# Seed for reproducibility
random.seed(42)
np.random.seed(42)


def load_config(config_path: str) -> dict:
    """Load YAML configuration."""
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)


def generate_timestamps(start: str, end: str, count: int) -> list:
    """Generate random timestamps within range."""
    start_dt = datetime.fromisoformat(start.replace('Z', '+00:00'))
    end_dt = datetime.fromisoformat(end.replace('Z', '+00:00'))
    delta_seconds = int((end_dt - start_dt).total_seconds())
    
    timestamps = []
    for _ in range(count):
        offset = random.randint(0, delta_seconds)
        ts = start_dt + timedelta(seconds=offset)
        timestamps.append(ts)
    
    return sorted(timestamps)


def is_business_hours(dt: datetime) -> bool:
    """Check if timestamp is during business hours (9am-6pm Mon-Fri)."""
    return (dt.weekday() < 5) and (9 <= dt.hour < 18)


def generate_k8s_audit_logs(config: dict) -> pd.DataFrame:
    """Generate K8s API server audit logs."""
    cfg = config['attack_config']
    benign_cfg = config['benign_config']
    time_window = config['time_window']
    row_count = config['row_counts']['k8s_audit_logs']
    
    # Calculate malicious vs benign split
    total_malicious_pods = cfg['compromised_tokens'] * \
                          ((cfg['pods_per_token']['min'] + cfg['pods_per_token']['max']) // 2)
    malicious_events = total_malicious_pods * 3  # create, start, running events
    benign_events = row_count - malicious_events
    
    records = []
    
    # Generate malicious pod creation events
    malicious_timestamps = generate_timestamps(
        time_window['start'], 
        time_window['end'], 
        malicious_events
    )
    
    # Filter by business/off-hours ratio
    malicious_timestamps_filtered = []
    for ts in malicious_timestamps:
        if is_business_hours(ts):
            if random.random() < (cfg['attack_timing']['business_hours_pct'] / 100):
                malicious_timestamps_filtered.append(ts)
        else:
            if random.random() < (cfg['attack_timing']['off_hours_pct'] / 100):
                malicious_timestamps_filtered.append(ts)
    
    # Adjust to match expected count
    while len(malicious_timestamps_filtered) < malicious_events:
        malicious_timestamps_filtered.append(random.choice(malicious_timestamps))
    malicious_timestamps_filtered = malicious_timestamps_filtered[:malicious_events]
    
    pod_id = 1000
    for ts in malicious_timestamps_filtered:
        namespace = random.choice(benign_cfg['namespaces'])
        registry = random.choice(cfg['malicious_registries'])
        image = f"{registry}/anonymous/miner:latest"
        
        # Pod creation event
        records.append({
            'timestamp': ts,
            'event_type': 'pod_create',
            'namespace': namespace,
            'pod_name': f'batch-job-{pod_id}',
            'pod_id': f'pod-{pod_id}',
            'user_agent': 'kubectl/v1.28.0',
            'source_ip': f'203.0.{random.randint(1,254)}.{random.randint(1,254)}',
            'service_account': f'sa-compromised-{random.randint(1, cfg["compromised_tokens"])}',
            'container_image': image,
            'registry_type': 'external',
            'resource_requests_cpu': random.randint(12, 16),
            'resource_requests_memory_gb': random.randint(24, 32),
            'resource_requests_gpu': 1,
            'privileged': False,
            'host_network': False,
            'response_code': 201,
            'is_malicious': True,
            'attack_chain_id': f'attack-{(pod_id // 6) + 1}'  # Group pods by attack
        })
        pod_id += 1
    
    # Generate benign pod creation events
    benign_timestamps = generate_timestamps(
        time_window['start'],
        time_window['end'],
        benign_events
    )
    
    for ts in benign_timestamps:
        namespace = random.choice(benign_cfg['namespaces'])
        registry = random.choice(benign_cfg['legitimate_registries'])
        image = f"{registry}/inference-server:v2.3.1"
        
        event_types = ['pod_create', 'pod_delete', 'pod_update', 'get_pods', 'list_secrets']
        event = random.choice(event_types)
        
        records.append({
            'timestamp': ts,
            'event_type': event,
            'namespace': namespace,
            'pod_name': f'inference-{random.randint(1000, 9999)}' if 'pod' in event else None,
            'pod_id': f'pod-benign-{random.randint(10000, 99999)}' if 'pod' in event else None,
            'user_agent': 'kubectl/v1.28.0',
            'source_ip': f'10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}',
            'service_account': f'sa-platform-{random.randint(1, 20)}',
            'container_image': image if event == 'pod_create' else None,
            'registry_type': 'internal' if event == 'pod_create' else None,
            'resource_requests_cpu': random.randint(4, 8) if event == 'pod_create' else None,
            'resource_requests_memory_gb': random.randint(8, 16) if event == 'pod_create' else None,
            'resource_requests_gpu': random.choice([0, 1]) if event == 'pod_create' else None,
            'privileged': False,
            'host_network': False,
            'response_code': random.choice([200, 201, 204]),
            'is_malicious': False,
            'attack_chain_id': None
        })
    
    df = pd.DataFrame(records)
    return df.sort_values('timestamp').reset_index(drop=True)


def generate_resource_metrics(config: dict, audit_logs: pd.DataFrame) -> pd.DataFrame:
    """Generate resource utilization metrics for pods."""
    cfg = config['attack_config']
    benign_cfg = config['benign_config']
    
    # Get pod creation events
    pod_creates = audit_logs[audit_logs['event_type'] == 'pod_create'].copy()
    
    records = []
    
    for _, pod in pod_creates.iterrows():
        # Generate hourly metrics for pod lifetime (assume 24-72 hours)
        lifetime_hours = random.randint(24, 72)
        
        for hour in range(lifetime_hours):
            metric_ts = pod['timestamp'] + timedelta(hours=hour)
            
            if pod['is_malicious']:
                # Malicious pods: high GPU/CPU usage
                gpu_util = random.randint(
                    cfg['resource_abuse']['gpu_utilization']['min'],
                    cfg['resource_abuse']['gpu_utilization']['max']
                )
                cpu_util = random.randint(
                    cfg['resource_abuse']['cpu_cores']['min'],
                    cfg['resource_abuse']['cpu_cores']['max']
                )
                memory_gb = random.randint(
                    cfg['resource_abuse']['memory_gb']['min'],
                    cfg['resource_abuse']['memory_gb']['max']
                )
            else:
                # Benign pods: normal usage
                gpu_util = random.randint(
                    benign_cfg['normal_resources']['gpu_utilization']['min'],
                    benign_cfg['normal_resources']['gpu_utilization']['max']
                ) if pod['resource_requests_gpu'] else 0
                cpu_util = random.randint(
                    benign_cfg['normal_resources']['cpu_cores']['min'],
                    benign_cfg['normal_resources']['cpu_cores']['max']
                )
                memory_gb = random.randint(
                    benign_cfg['normal_resources']['memory_gb']['min'],
                    benign_cfg['normal_resources']['memory_gb']['max']
                )
            
            records.append({
                'timestamp': metric_ts,
                'namespace': pod['namespace'],
                'pod_id': pod['pod_id'],
                'pod_name': pod['pod_name'],
                'cpu_cores_used': cpu_util,
                'memory_gb_used': memory_gb,
                'gpu_utilization_pct': gpu_util,
                'network_rx_bytes': random.randint(1000000, 10000000),  # 1-10 MB
                'network_tx_bytes': random.randint(1000000, 10000000),
                'is_malicious': pod['is_malicious'],
                'attack_chain_id': pod['attack_chain_id']
            })
    
    df = pd.DataFrame(records)
    return df.sort_values('timestamp').reset_index(drop=True)


def generate_network_flows(config: dict, audit_logs: pd.DataFrame) -> pd.DataFrame:
    """Generate network egress flows from pods."""
    cfg = config['attack_config']
    
    # Get malicious pod creation events
    malicious_pods = audit_logs[
        (audit_logs['event_type'] == 'pod_create') & 
        (audit_logs['is_malicious'] == True)
    ].copy()
    
    records = []
    
    for _, pod in malicious_pods.iterrows():
        # Each malicious pod connects to mining pool
        lifetime_hours = random.randint(24, 72)
        
        for hour in range(lifetime_hours):
            flow_ts = pod['timestamp'] + timedelta(hours=hour)
            mining_pool = random.choice(cfg['mining_pools'])
            pool_host, pool_port = mining_pool.split(':')
            
            # Generate connection to mining pool
            records.append({
                'timestamp': flow_ts,
                'namespace': pod['namespace'],
                'pod_id': pod['pod_id'],
                'pod_name': pod['pod_name'],
                'src_ip': f'10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}',
                'dst_ip': f'203.0.{random.randint(1,254)}.{random.randint(1,254)}',  # External
                'dst_host': pool_host,
                'dst_port': int(pool_port),
                'protocol': 'tcp',
                'bytes_sent': int(random.uniform(
                    cfg['egress_volume_gb']['min'] * 1e9 / 24,  # Per hour
                    cfg['egress_volume_gb']['max'] * 1e9 / 24
                )),
                'bytes_received': random.randint(100000, 500000),  # Small responses
                'connection_duration_sec': random.randint(3000, 3600),
                'is_mining_pool': True,
                'is_malicious': True,
                'attack_chain_id': pod['attack_chain_id']
            })
    
    # Add benign egress (to legitimate services)
    benign_pods = audit_logs[
        (audit_logs['event_type'] == 'pod_create') & 
        (audit_logs['is_malicious'] == False)
    ].copy()
    
    for _, pod in benign_pods.head(100).iterrows():  # Subset for performance
        flow_ts = pod['timestamp'] + timedelta(hours=random.randint(0, 24))
        
        records.append({
            'timestamp': flow_ts,
            'namespace': pod['namespace'],
            'pod_id': pod['pod_id'],
            'pod_name': pod['pod_name'],
            'src_ip': f'10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}',
            'dst_ip': f'10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}',
            'dst_host': 'internal-api.company.com',
            'dst_port': 443,
            'protocol': 'tcp',
            'bytes_sent': random.randint(10000, 100000),
            'bytes_received': random.randint(10000, 100000),
            'connection_duration_sec': random.randint(10, 300),
            'is_mining_pool': False,
            'is_malicious': False,
            'attack_chain_id': None
        })
    
    df = pd.DataFrame(records)
    return df.sort_values('timestamp').reset_index(drop=True)


def main():
    parser = argparse.ArgumentParser(description='Generate CASE-0004 K8s synthetic data')
    parser.add_argument('--config', required=True, help='Path to case0004.yaml')
    parser.add_argument('--out', default='datasets/output_case0004', help='Output directory')
    args = parser.parse_args()
    
    # Load configuration
    config = load_config(args.config)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"Generating CASE-0004: {config['case_name']}")
    print(f"Time window: {config['time_window']['start']} to {config['time_window']['end']}")
    print(f"Expected malicious pods: {config['ground_truth']['total_malicious_pods']}")
    
    # Generate telemetry tables
    print("\n[1/3] Generating K8s audit logs...")
    audit_logs = generate_k8s_audit_logs(config)
    audit_logs.to_parquet(out_dir / 'k8s_audit_logs.parquet', index=False)
    print(f"  ✓ Generated {len(audit_logs):,} audit events")
    print(f"  ✓ Malicious pod creations: {audit_logs['is_malicious'].sum():,}")
    
    print("\n[2/3] Generating resource metrics...")
    resource_metrics = generate_resource_metrics(config, audit_logs)
    resource_metrics.to_parquet(out_dir / 'resource_metrics.parquet', index=False)
    print(f"  ✓ Generated {len(resource_metrics):,} metric samples")
    
    print("\n[3/3] Generating network flows...")
    network_flows = generate_network_flows(config, audit_logs)
    network_flows.to_parquet(out_dir / 'network_flows.parquet', index=False)
    print(f"  ✓ Generated {len(network_flows):,} network flows")
    print(f"  ✓ Mining pool connections: {network_flows['is_mining_pool'].sum():,}")
    
    # Summary
    print("\n" + "="*60)
    print("CASE-0004 Data Generation Complete")
    print("="*60)
    print(f"Output directory: {out_dir}")
    print(f"\nGround truth:")
    print(f"  Total malicious pods: {audit_logs[audit_logs['is_malicious'] == True]['pod_id'].nunique()}")
    print(f"  Compromised service accounts: {config['attack_config']['compromised_tokens']}")
    print(f"  Attack chains: {audit_logs[audit_logs['is_malicious'] == True]['attack_chain_id'].nunique()}")


if __name__ == '__main__':
    main()
