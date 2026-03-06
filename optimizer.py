"""
AWS Cost & Security Optimization Scanner
Identifies waste, security risks, and right-sizing opportunities:
  1. Unattached EBS Volumes (paying for storage not in use)
  2. Unused Elastic IPs (charged when not associated)
  3. Old EBS Snapshots (>90 days, potential savings)
  4. Idle/Stopped EC2 Instances (stopped but still incurring EBS costs)
  5. Previous Generation Instance Types (upgrade candidates)
  6. Unattached/Unused NAT Gateways
  7. Public S3 Buckets (security risk)
  8. Unused Load Balancers (no healthy targets)
  9. CloudWatch: Low-utilization EC2 (avg CPU <5% over 7 days)
  10. GP2 volumes that should be GP3 (cheaper & faster)
"""

import boto3
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

PREVIOUS_GEN_TYPES = {
    "t1.", "t2.", "m1.", "m2.", "m3.", "m4.", "c1.", "c3.", "c4.",
    "r3.", "r4.", "i2.", "i3.", "d2.", "g2.", "g3.", "p2.",
}

ALL_REGIONS = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "af-south-1", "ap-east-1", "ap-south-1", "ap-south-2",
    "ap-southeast-1", "ap-southeast-2", "ap-southeast-3", "ap-southeast-4",
    "ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
    "ca-central-1", "ca-west-1",
    "eu-central-1", "eu-central-2", "eu-west-1", "eu-west-2", "eu-west-3",
    "eu-south-1", "eu-south-2", "eu-north-1",
    "il-central-1", "me-south-1", "me-central-1", "sa-east-1",
]

EBS_PRICE_PER_GB = {
    "gp2": 0.10, "gp3": 0.08, "io1": 0.125, "io2": 0.125,
    "st1": 0.045, "sc1": 0.015, "standard": 0.05,
}

EIP_MONTHLY_COST = 3.60  # per unused EIP per month (approx)
NAT_GW_MONTHLY_COST = 32.40  # per NAT GW per month (approx)


def _scan_region_optimization(session_kwargs, region):
    """Scan a single region for optimization opportunities."""
    sess = boto3.Session(**session_kwargs, region_name=region)
    findings = []

    try:
        ec2 = sess.client("ec2")
    except Exception:
        return findings

    # 1. Unattached EBS Volumes
    try:
        vols = ec2.describe_volumes(
            Filters=[{"Name": "status", "Values": ["available"]}]
        ).get("Volumes", [])
        for v in vols:
            size = v["Size"]
            vtype = v.get("VolumeType", "gp2")
            monthly = size * EBS_PRICE_PER_GB.get(vtype, 0.10)
            findings.append({
                "category": "Cost",
                "severity": "High" if monthly > 10 else "Medium",
                "resource_type": "EBS Volume",
                "resource_id": v["VolumeId"],
                "region": region,
                "issue": "Unattached EBS Volume",
                "detail": f"{size} GB {vtype}, not attached to any instance",
                "estimated_monthly_waste": round(monthly, 2),
                "recommendation": "Delete if no longer needed, or create a snapshot and delete",
            })
    except Exception:
        pass

    # 2. Unused Elastic IPs
    try:
        eips = ec2.describe_addresses().get("Addresses", [])
        for e in eips:
            if not e.get("AssociationId"):
                findings.append({
                    "category": "Cost",
                    "severity": "Medium",
                    "resource_type": "Elastic IP",
                    "resource_id": e.get("AllocationId", e.get("PublicIp", "")),
                    "region": region,
                    "issue": "Unused Elastic IP",
                    "detail": f"IP {e.get('PublicIp', 'N/A')} not associated with any instance",
                    "estimated_monthly_waste": EIP_MONTHLY_COST,
                    "recommendation": "Release if not needed",
                })
    except Exception:
        pass

    # 3. Old EBS Snapshots (>90 days)
    try:
        snaps = ec2.describe_snapshots(OwnerIds=["self"]).get("Snapshots", [])
        cutoff = datetime.utcnow() - timedelta(days=90)
        for s in snaps:
            start_time = s.get("StartTime")
            if start_time and start_time.replace(tzinfo=None) < cutoff:
                age_days = (datetime.utcnow() - start_time.replace(tzinfo=None)).days
                size = s.get("VolumeSize", 0)
                monthly = size * 0.05  # snapshot storage ~$0.05/GB
                findings.append({
                    "category": "Cost",
                    "severity": "Low",
                    "resource_type": "EBS Snapshot",
                    "resource_id": s["SnapshotId"],
                    "region": region,
                    "issue": "Old EBS Snapshot (>90 days)",
                    "detail": f"{size} GB, {age_days} days old, Desc: {s.get('Description', '')[:60]}",
                    "estimated_monthly_waste": round(monthly, 2),
                    "recommendation": "Review and delete if no longer needed for recovery",
                })
    except Exception:
        pass

    # 4. Stopped EC2 Instances (still paying for EBS)
    try:
        reservations = ec2.describe_instances(
            Filters=[{"Name": "instance-state-name", "Values": ["stopped"]}]
        ).get("Reservations", [])
        for r in reservations:
            for inst in r["Instances"]:
                name = ""
                for tag in inst.get("Tags", []):
                    if tag["Key"] == "Name":
                        name = tag["Value"]
                # Calculate attached EBS cost
                ebs_cost = 0
                for bdm in inst.get("BlockDeviceMappings", []):
                    vol_id = bdm.get("Ebs", {}).get("VolumeId")
                    if vol_id:
                        try:
                            vr = ec2.describe_volumes(VolumeIds=[vol_id])
                            for vv in vr.get("Volumes", []):
                                vtype = vv.get("VolumeType", "gp2")
                                ebs_cost += vv["Size"] * EBS_PRICE_PER_GB.get(vtype, 0.10)
                        except Exception:
                            pass
                findings.append({
                    "category": "Cost",
                    "severity": "High" if ebs_cost > 20 else "Medium",
                    "resource_type": "EC2 Instance",
                    "resource_id": inst["InstanceId"],
                    "region": region,
                    "issue": "Stopped Instance (EBS still charged)",
                    "detail": f"{name or 'N/A'} ({inst['InstanceType']}), stopped but EBS attached",
                    "estimated_monthly_waste": round(ebs_cost, 2),
                    "recommendation": "Terminate if not needed, or snapshot EBS and terminate",
                })
    except Exception:
        pass

    # 5. Previous Generation Instance Types
    try:
        reservations = ec2.describe_instances(
            Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
        ).get("Reservations", [])
        for r in reservations:
            for inst in r["Instances"]:
                itype = inst["InstanceType"]
                if any(itype.startswith(p) for p in PREVIOUS_GEN_TYPES):
                    name = ""
                    for tag in inst.get("Tags", []):
                        if tag["Key"] == "Name":
                            name = tag["Value"]
                    findings.append({
                        "category": "Optimization",
                        "severity": "Medium",
                        "resource_type": "EC2 Instance",
                        "resource_id": inst["InstanceId"],
                        "region": region,
                        "issue": "Previous Generation Instance Type",
                        "detail": f"{name or 'N/A'} using {itype}",
                        "estimated_monthly_waste": 0,
                        "recommendation": f"Upgrade to current-gen equivalent for better price/performance",
                    })
    except Exception:
        pass

    # 6. GP2 volumes -> GP3 migration candidates
    try:
        vols = ec2.describe_volumes(
            Filters=[{"Name": "volume-type", "Values": ["gp2"]}]
        ).get("Volumes", [])
        for v in vols:
            size = v["Size"]
            gp2_cost = size * 0.10
            gp3_cost = size * 0.08
            saving = gp2_cost - gp3_cost
            if saving > 0:
                findings.append({
                    "category": "Optimization",
                    "severity": "Medium" if saving > 5 else "Low",
                    "resource_type": "EBS Volume",
                    "resource_id": v["VolumeId"],
                    "region": region,
                    "issue": "GP2 Volume - Migrate to GP3",
                    "detail": f"{size} GB gp2 volume, gp3 is cheaper and faster",
                    "estimated_monthly_waste": round(saving, 2),
                    "recommendation": "Migrate to gp3 (20% cheaper, better baseline IOPS/throughput)",
                })
    except Exception:
        pass

    # 7. Unused NAT Gateways (available but check if routes use them)
    try:
        nats = ec2.describe_nat_gateways(
            Filter=[{"Name": "state", "Values": ["available"]}]
        ).get("NatGateways", [])
        for n in nats:
            # Check if any route table references this NAT GW
            nat_id = n["NatGatewayId"]
            routes = ec2.describe_route_tables().get("RouteTables", [])
            in_use = False
            for rt in routes:
                for route in rt.get("Routes", []):
                    if route.get("NatGatewayId") == nat_id:
                        in_use = True
                        break
                if in_use:
                    break
            if not in_use:
                findings.append({
                    "category": "Cost",
                    "severity": "High",
                    "resource_type": "NAT Gateway",
                    "resource_id": nat_id,
                    "region": region,
                    "issue": "NAT Gateway not referenced in any route table",
                    "detail": f"NAT GW {nat_id} is available but no routes point to it",
                    "estimated_monthly_waste": NAT_GW_MONTHLY_COST,
                    "recommendation": "Delete if no longer needed (costs ~$32/month + data)",
                })
    except Exception:
        pass

    # 8. Unused Load Balancers (no targets / no instances)
    try:
        elbv2 = sess.client("elbv2")
        lbs = elbv2.describe_load_balancers().get("LoadBalancers", [])
        for lb in lbs:
            lb_arn = lb["LoadBalancerArn"]
            tgs = elbv2.describe_target_groups(
                LoadBalancerArn=lb_arn
            ).get("TargetGroups", [])
            has_targets = False
            for tg in tgs:
                health = elbv2.describe_target_health(
                    TargetGroupArn=tg["TargetGroupArn"]
                ).get("TargetHealthDescriptions", [])
                if health:
                    has_targets = True
                    break
            if not has_targets:
                findings.append({
                    "category": "Cost",
                    "severity": "High",
                    "resource_type": "Load Balancer",
                    "resource_id": lb["LoadBalancerName"],
                    "region": region,
                    "issue": "Load Balancer with no healthy targets",
                    "detail": f"{lb['Type']} LB '{lb['LoadBalancerName']}' has no registered targets",
                    "estimated_monthly_waste": 16.20,  # ~ALB minimum
                    "recommendation": "Delete if no longer serving traffic",
                })
    except Exception:
        pass

    # 9. Low CPU Utilization (avg <5% over last 7 days)
    try:
        cw = sess.client("cloudwatch")
        reservations = ec2.describe_instances(
            Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
        ).get("Reservations", [])
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=7)
        for r in reservations:
            for inst in r["Instances"]:
                try:
                    stats = cw.get_metric_statistics(
                        Namespace="AWS/EC2",
                        MetricName="CPUUtilization",
                        Dimensions=[{"Name": "InstanceId", "Value": inst["InstanceId"]}],
                        StartTime=start_time, EndTime=end_time,
                        Period=86400, Statistics=["Average"],
                    )
                    datapoints = stats.get("Datapoints", [])
                    if datapoints:
                        avg_cpu = sum(d["Average"] for d in datapoints) / len(datapoints)
                        if avg_cpu < 5.0:
                            name = ""
                            for tag in inst.get("Tags", []):
                                if tag["Key"] == "Name":
                                    name = tag["Value"]
                            findings.append({
                                "category": "Optimization",
                                "severity": "Medium",
                                "resource_type": "EC2 Instance",
                                "resource_id": inst["InstanceId"],
                                "region": region,
                                "issue": "Low CPU Utilization (<5% avg over 7 days)",
                                "detail": f"{name or 'N/A'} ({inst['InstanceType']}), avg CPU: {avg_cpu:.1f}%",
                                "estimated_monthly_waste": 0,
                                "recommendation": "Consider downsizing or using a smaller instance type",
                            })
                except Exception:
                    pass
    except Exception:
        pass

    return findings


def _scan_s3_security(session):
    """Check for public S3 buckets."""
    findings = []
    try:
        s3 = session.client("s3")
        s3control = session.client("s3control")
        buckets = s3.list_buckets().get("Buckets", [])

        for b in buckets:
            bucket_name = b["Name"]
            try:
                # Check bucket public access block
                try:
                    pab = s3.get_public_access_block(Bucket=bucket_name)
                    config = pab.get("PublicAccessBlockConfiguration", {})
                    all_blocked = (
                        config.get("BlockPublicAcls", False) and
                        config.get("IgnorePublicAcls", False) and
                        config.get("BlockPublicPolicy", False) and
                        config.get("RestrictPublicBuckets", False)
                    )
                    if not all_blocked:
                        loc = "us-east-1"
                        try:
                            lr = s3.get_bucket_location(Bucket=bucket_name)
                            loc = lr.get("LocationConstraint") or "us-east-1"
                        except Exception:
                            pass
                        findings.append({
                            "category": "Security",
                            "severity": "Critical",
                            "resource_type": "S3 Bucket",
                            "resource_id": bucket_name,
                            "region": loc,
                            "issue": "S3 Bucket not fully blocking public access",
                            "detail": f"Public access block is not fully enabled",
                            "estimated_monthly_waste": 0,
                            "recommendation": "Enable all 4 public access block settings unless public access is intended",
                        })
                except s3.exceptions.ClientError as e:
                    if "NoSuchPublicAccessBlockConfiguration" in str(e):
                        loc = "us-east-1"
                        try:
                            lr = s3.get_bucket_location(Bucket=bucket_name)
                            loc = lr.get("LocationConstraint") or "us-east-1"
                        except Exception:
                            pass
                        findings.append({
                            "category": "Security",
                            "severity": "Critical",
                            "resource_type": "S3 Bucket",
                            "resource_id": bucket_name,
                            "region": loc,
                            "issue": "S3 Bucket has no public access block configured",
                            "detail": "No public access block configuration found",
                            "estimated_monthly_waste": 0,
                            "recommendation": "Enable public access block on this bucket immediately",
                        })
            except Exception:
                pass

            # Check bucket encryption
            try:
                s3.get_bucket_encryption(Bucket=bucket_name)
            except Exception as e:
                if "ServerSideEncryptionConfigurationNotFoundError" in str(e):
                    loc = "us-east-1"
                    try:
                        lr = s3.get_bucket_location(Bucket=bucket_name)
                        loc = lr.get("LocationConstraint") or "us-east-1"
                    except Exception:
                        pass
                    findings.append({
                        "category": "Security",
                        "severity": "High",
                        "resource_type": "S3 Bucket",
                        "resource_id": bucket_name,
                        "region": loc,
                        "issue": "S3 Bucket without default encryption",
                        "detail": "No server-side encryption configuration",
                        "estimated_monthly_waste": 0,
                        "recommendation": "Enable default SSE-S3 or SSE-KMS encryption",
                    })
    except Exception:
        pass

    return findings


def _check_iam_security(session):
    """Check for IAM security issues."""
    findings = []
    try:
        iam = session.client("iam")

        # Check for root account access keys
        try:
            summary = iam.get_account_summary().get("SummaryMap", {})
            if summary.get("AccountAccessKeysPresent", 0) > 0:
                findings.append({
                    "category": "Security",
                    "severity": "Critical",
                    "resource_type": "IAM",
                    "resource_id": "Root Account",
                    "region": "global",
                    "issue": "Root account has access keys",
                    "detail": "Root access keys are a critical security risk",
                    "estimated_monthly_waste": 0,
                    "recommendation": "Delete root access keys immediately and use IAM users instead",
                })
            if summary.get("AccountMFAEnabled", 0) == 0:
                findings.append({
                    "category": "Security",
                    "severity": "Critical",
                    "resource_type": "IAM",
                    "resource_id": "Root Account",
                    "region": "global",
                    "issue": "Root account MFA not enabled",
                    "detail": "Root account does not have MFA configured",
                    "estimated_monthly_waste": 0,
                    "recommendation": "Enable MFA on root account immediately",
                })
        except Exception:
            pass

        # Check for users without MFA
        try:
            users = iam.list_users().get("Users", [])
            for u in users:
                mfa_devices = iam.list_mfa_devices(
                    UserName=u["UserName"]
                ).get("MFADevices", [])
                if not mfa_devices:
                    # Check if user has console access
                    try:
                        iam.get_login_profile(UserName=u["UserName"])
                        findings.append({
                            "category": "Security",
                            "severity": "High",
                            "resource_type": "IAM User",
                            "resource_id": u["UserName"],
                            "region": "global",
                            "issue": "IAM User with console access but no MFA",
                            "detail": f"User '{u['UserName']}' has console login but no MFA device",
                            "estimated_monthly_waste": 0,
                            "recommendation": "Enable MFA for this user",
                        })
                    except Exception:
                        pass  # No console access = less critical

                # Check for old access keys (>90 days)
                keys = iam.list_access_keys(UserName=u["UserName"]).get("AccessKeyMetadata", [])
                for k in keys:
                    if k["Status"] == "Active":
                        created = k["CreateDate"].replace(tzinfo=None)
                        age = (datetime.utcnow() - created).days
                        if age > 90:
                            findings.append({
                                "category": "Security",
                                "severity": "Medium",
                                "resource_type": "IAM Access Key",
                                "resource_id": f"{u['UserName']} / {k['AccessKeyId']}",
                                "region": "global",
                                "issue": f"Access Key older than 90 days ({age} days)",
                                "detail": f"Key {k['AccessKeyId']} for user '{u['UserName']}'",
                                "estimated_monthly_waste": 0,
                                "recommendation": "Rotate access keys regularly (every 90 days)",
                            })
        except Exception:
            pass

    except Exception:
        pass

    return findings


def run_optimization_scan(access_key, secret_key, account_label=""):
    """Run full optimization scan. Yields progress updates."""
    session = boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name="us-east-1",
    )

    # Verify identity
    yield ("connect", "running", f"Connecting to AWS as {account_label}...")
    try:
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        account_id = identity["Account"]
        yield ("connect", "done", {"account_id": account_id})
    except Exception as e:
        yield ("connect", "error", str(e))
        return

    all_findings = []

    # S3 Security
    yield ("s3_security", "running", "Checking S3 bucket security...")
    try:
        s3_findings = _scan_s3_security(session)
        all_findings.extend(s3_findings)
        yield ("s3_security", "done", f"{len(s3_findings)} finding(s)")
    except Exception as e:
        yield ("s3_security", "error", str(e))

    # IAM Security
    yield ("iam_security", "running", "Checking IAM security posture...")
    try:
        iam_findings = _check_iam_security(session)
        all_findings.extend(iam_findings)
        yield ("iam_security", "done", f"{len(iam_findings)} finding(s)")
    except Exception as e:
        yield ("iam_security", "error", str(e))

    # Region-level scans in parallel
    yield ("regions", "running", "Scanning all regions for optimization opportunities...")
    creds = session.get_credentials().get_frozen_credentials()
    session_kwargs = {
        "aws_access_key_id": creds.access_key,
        "aws_secret_access_key": creds.secret_key,
    }
    if creds.token:
        session_kwargs["aws_session_token"] = creds.token

    try:
        with ThreadPoolExecutor(max_workers=12) as pool:
            futures = {
                pool.submit(_scan_region_optimization, session_kwargs, r): r
                for r in ALL_REGIONS
            }
            for future in as_completed(futures):
                try:
                    region_findings = future.result()
                    all_findings.extend(region_findings)
                except Exception:
                    pass
        yield ("regions", "done", f"{len(all_findings)} total finding(s) so far")
    except Exception as e:
        yield ("regions", "error", str(e))

    # Build summary
    total_waste = sum(f.get("estimated_monthly_waste", 0) for f in all_findings)
    by_category = {}
    by_severity = {}
    for f in all_findings:
        cat = f.get("category", "Other")
        sev = f.get("severity", "Low")
        by_category[cat] = by_category.get(cat, 0) + 1
        by_severity[sev] = by_severity.get(sev, 0) + 1

    result = {
        "account_label": account_label,
        "account_id": account_id,
        "scan_timestamp": datetime.utcnow().isoformat() + "Z",
        "findings": all_findings,
        "summary": {
            "total_findings": len(all_findings),
            "estimated_monthly_waste": round(total_waste, 2),
            "estimated_annual_waste": round(total_waste * 12, 2),
            "by_category": by_category,
            "by_severity": by_severity,
        },
    }

    yield ("complete", "done", result)
