"""
AWS Internal Audit - Backend Logic
Matches the exact 6-point internal audit checklist:
  1. Billing: Last Month Total Cost + Current Month Forecasted Cost
  2. Payments: Outstanding/due bills from Billing > Payments
  3. Region & Service Tracking: ALL services in ALL regions (even single volume/snapshot)
  4. Organization Verification: Org ID + Management Account Email match
  5. Quota Checks: EC2 On-Demand Standard, G&VT instances, Elastic IPs
  6. Last Updated timestamp
"""

import boto3
from datetime import datetime, timedelta, date
from calendar import monthrange
from concurrent.futures import ThreadPoolExecutor, as_completed

# Regions for quota checks (Step 5)
QUOTA_REGIONS = {
    "us-east-1": "North Virginia",
    "ap-south-1": "Mumbai",
    "ap-south-2": "Hyderabad",
    "ap-southeast-1": "Singapore",
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

REGION_NAMES = {
    "us-east-1": "N. Virginia", "us-east-2": "Ohio",
    "us-west-1": "N. California", "us-west-2": "Oregon",
    "af-south-1": "Cape Town", "ap-east-1": "Hong Kong",
    "ap-south-1": "Mumbai", "ap-south-2": "Hyderabad",
    "ap-southeast-1": "Singapore", "ap-southeast-2": "Sydney",
    "ap-southeast-3": "Jakarta", "ap-southeast-4": "Melbourne",
    "ap-northeast-1": "Tokyo", "ap-northeast-2": "Seoul",
    "ap-northeast-3": "Osaka", "ca-central-1": "Canada",
    "ca-west-1": "Calgary", "eu-central-1": "Frankfurt",
    "eu-central-2": "Zurich", "eu-west-1": "Ireland",
    "eu-west-2": "London", "eu-west-3": "Paris",
    "eu-south-1": "Milan", "eu-south-2": "Spain",
    "eu-north-1": "Stockholm", "il-central-1": "Tel Aviv",
    "me-south-1": "Bahrain", "me-central-1": "UAE",
    "sa-east-1": "Sao Paulo",
}


def get_session(access_key, secret_key, region="us-east-1"):
    return boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=region,
    )


def get_account_identity(session):
    sts = session.client("sts")
    identity = sts.get_caller_identity()
    return {
        "account_id": identity["Account"],
        "arn": identity["Arn"],
        "user_id": identity["UserId"],
    }


# ═══════════════════════════════════════════════════════════════════════
# STEP 1: Billing & Cost Management > Home
#   - Last Month's Total Cost
#   - Current Month Forecasted Cost
# ═══════════════════════════════════════════════════════════════════════

def get_billing_analysis(session, year=None, month=None):
    ce = session.client("ce", region_name="us-east-1")
    today = datetime.utcnow().date()

    # Last month boundaries (or custom month)
    if year and month:
        target_start = date(year, month, 1)
        _, last_day = monthrange(year, month)
        target_end = date(year, month, last_day)
        if month == 12:
            ce_end = date(year + 1, 1, 1)
        else:
            ce_end = date(year, month + 1, 1)
    else:
        first_of_this_month = today.replace(day=1)
        target_end = first_of_this_month - timedelta(days=1)
        target_start = target_end.replace(day=1)
        ce_end = first_of_this_month

    # Current month for forecast
    current_month_start = today.replace(day=1)
    if today.month == 12:
        next_month_start = today.replace(year=today.year + 1, month=1, day=1)
    else:
        next_month_start = today.replace(month=today.month + 1, day=1)

    result = {
        "target_month": f"{target_start.strftime('%B %Y')}",
        "target_period": f"{target_start} to {target_end}",
        "last_month_total_cost": "N/A",
        "currency": "USD",
        "forecasted_cost_current_month": "N/A",
        "forecast_currency": "USD",
    }

    # Last Month's Total Cost
    try:
        resp = ce.get_cost_and_usage(
            TimePeriod={"Start": str(target_start), "End": str(ce_end)},
            Granularity="MONTHLY",
            Metrics=["UnblendedCost"],
        )
        for p in resp.get("ResultsByTime", []):
            amt = p["Total"]["UnblendedCost"]["Amount"]
            result["last_month_total_cost"] = f"{float(amt):.2f}"
            result["currency"] = p["Total"]["UnblendedCost"]["Unit"]
    except Exception as e:
        result["last_month_total_cost"] = f"Error: {e}"

    # Current Month Forecasted Cost
    try:
        resp = ce.get_cost_forecast(
            TimePeriod={"Start": str(today), "End": str(next_month_start)},
            Metric="UNBLENDED_COST",
            Granularity="MONTHLY",
        )
        result["forecasted_cost_current_month"] = f"{float(resp['Total']['Amount']):.2f}"
        result["forecast_currency"] = resp["Total"]["Unit"]
    except Exception as e:
        result["forecasted_cost_current_month"] = f"Error: {e}"

    return result


# ═══════════════════════════════════════════════════════════════════════
# STEP 2: Billing & Cost Management > Payments
#   - Total Outstanding Balance / bills due
# ═══════════════════════════════════════════════════════════════════════

def get_payment_status(session):
    ce = session.client("ce", region_name="us-east-1")
    today = datetime.utcnow().date()
    first_of_this_month = today.replace(day=1)

    result = {
        "outstanding_balance": "N/A",
        "currency": "USD",
        "payment_due": "No",
        "billing_alerts": [],
    }

    # Current month accrued = what's outstanding right now
    try:
        resp = ce.get_cost_and_usage(
            TimePeriod={"Start": str(first_of_this_month), "End": str(today)},
            Granularity="MONTHLY",
            Metrics=["UnblendedCost"],
        )
        for p in resp.get("ResultsByTime", []):
            amt = float(p["Total"]["UnblendedCost"]["Amount"])
            result["outstanding_balance"] = f"{amt:.2f}"
            result["currency"] = p["Total"]["UnblendedCost"]["Unit"]
            if amt > 0:
                result["payment_due"] = "Yes"
    except Exception as e:
        result["outstanding_balance"] = f"Error: {e}"

    # Billing alarms from CloudWatch
    try:
        cw = session.client("cloudwatch", region_name="us-east-1")
        alarms = cw.describe_alarms(AlarmNamePrefix="Billing", StateValue="ALARM",
                                    MaxRecords=10)
        for a in alarms.get("MetricAlarms", []):
            result["billing_alerts"].append({
                "name": a["AlarmName"], "state": a["StateValue"],
                "reason": a.get("StateReason", ""),
            })
    except Exception:
        pass

    return result


# ═══════════════════════════════════════════════════════════════════════
# STEP 3: Billing > Bills — Region & Service Tracking
#   - Check last month + current month bills
#   - Every region where ANY service runs
#   - Even a single volume, snapshot, EIP counts
#   - Service-by-region cost breakdown from Bills page
# ═══════════════════════════════════════════════════════════════════════

def get_bills_by_service_region(session, year=None, month=None):
    """
    Replicates Billing > Bills page: cost broken down by Service + Region
    for both last month and current month.
    """
    ce = session.client("ce", region_name="us-east-1")
    today = datetime.utcnow().date()

    # Last month
    first_of_this_month = today.replace(day=1)
    if year and month:
        last_start = date(year, month, 1)
        if month == 12:
            last_end = date(year + 1, 1, 1)
        else:
            last_end = date(year, month + 1, 1)
    else:
        last_end = first_of_this_month
        last_start = (last_end - timedelta(days=1)).replace(day=1)

    # Current month
    curr_start = first_of_this_month
    curr_end = today

    bills = {"last_month": [], "current_month": []}

    for label, start, end in [
        ("last_month", str(last_start), str(last_end)),
        ("current_month", str(curr_start), str(curr_end)),
    ]:
        try:
            resp = ce.get_cost_and_usage(
                TimePeriod={"Start": start, "End": end},
                Granularity="MONTHLY",
                Metrics=["UnblendedCost"],
                GroupBy=[
                    {"Type": "DIMENSION", "Key": "SERVICE"},
                    {"Type": "DIMENSION", "Key": "REGION"},
                ],
            )
            for period in resp.get("ResultsByTime", []):
                for group in period.get("Groups", []):
                    keys = group["Keys"]
                    cost = float(group["Metrics"]["UnblendedCost"]["Amount"])
                    if cost > 0.0:
                        bills[label].append({
                            "Service": keys[0],
                            "Region": keys[1] if len(keys) > 1 else "global",
                            "Cost (USD)": f"{cost:.4f}",
                        })
        except Exception:
            pass

    return bills


def _scan_region(session_kwargs, region):
    """Scan a single region for ALL active resources — even a single snapshot."""
    sess = boto3.Session(**session_kwargs, region_name=region)
    findings = {}

    # EC2 Instances
    try:
        ec2 = sess.client("ec2")
        reservations = ec2.describe_instances(
            Filters=[{"Name": "instance-state-name", "Values": ["running", "stopped"]}]
        ).get("Reservations", [])
        items = []
        for r in reservations:
            for inst in r["Instances"]:
                name = ""
                for tag in inst.get("Tags", []):
                    if tag["Key"] == "Name":
                        name = tag["Value"]
                items.append({
                    "ID": inst["InstanceId"], "Name": name,
                    "Type": inst["InstanceType"], "State": inst["State"]["Name"],
                })
        if items:
            findings["EC2 Instances"] = items
    except Exception:
        pass

    # EBS Volumes (even a single one)
    try:
        vols = ec2.describe_volumes().get("Volumes", [])
        if vols:
            findings["EBS Volumes"] = [
                {"ID": v["VolumeId"], "Size(GB)": v["Size"],
                 "State": v["State"], "Type": v.get("VolumeType", "")}
                for v in vols
            ]
    except Exception:
        pass

    # EBS Snapshots (even a single one)
    try:
        snaps = ec2.describe_snapshots(OwnerIds=["self"]).get("Snapshots", [])
        if snaps:
            findings["EBS Snapshots"] = [
                {"ID": s["SnapshotId"], "Size(GB)": s["VolumeSize"],
                 "State": s["State"]}
                for s in snaps
            ]
    except Exception:
        pass

    # Elastic IPs
    try:
        eips = ec2.describe_addresses().get("Addresses", [])
        if eips:
            findings["Elastic IPs"] = [
                {"IP": e.get("PublicIp", ""), "AllocationId": e.get("AllocationId", ""),
                 "Associated": "Yes" if e.get("AssociationId") else "No"}
                for e in eips
            ]
    except Exception:
        pass

    # S3 not here — scanned globally

    # RDS
    try:
        rds = sess.client("rds")
        dbs = rds.describe_db_instances().get("DBInstances", [])
        if dbs:
            findings["RDS Instances"] = [
                {"ID": d["DBInstanceIdentifier"], "Engine": d["Engine"],
                 "Class": d["DBInstanceClass"], "Status": d["DBInstanceStatus"]}
                for d in dbs
            ]
    except Exception:
        pass

    # Lambda
    try:
        lam = sess.client("lambda")
        funcs = lam.list_functions().get("Functions", [])
        if funcs:
            findings["Lambda Functions"] = [
                {"Name": f["FunctionName"], "Runtime": f.get("Runtime", "N/A")}
                for f in funcs
            ]
    except Exception:
        pass

    # Load Balancers (ALB/NLB)
    try:
        elbv2 = sess.client("elbv2")
        lbs = elbv2.describe_load_balancers().get("LoadBalancers", [])
        if lbs:
            findings["Load Balancers"] = [
                {"Name": lb["LoadBalancerName"], "Type": lb["Type"],
                 "State": lb["State"]["Code"]}
                for lb in lbs
            ]
    except Exception:
        pass

    # Classic ELB
    try:
        elb = sess.client("elb")
        clbs = elb.describe_load_balancers().get("LoadBalancerDescriptions", [])
        if clbs:
            findings["Classic Load Balancers"] = [
                {"Name": lb["LoadBalancerName"], "DNS": lb.get("DNSName", "")}
                for lb in clbs
            ]
    except Exception:
        pass

    # NAT Gateways
    try:
        nats = ec2.describe_nat_gateways(
            Filter=[{"Name": "state", "Values": ["available", "pending"]}]
        ).get("NatGateways", [])
        if nats:
            findings["NAT Gateways"] = [
                {"ID": n["NatGatewayId"], "State": n["State"]}
                for n in nats
            ]
    except Exception:
        pass

    # VPCs (non-default)
    try:
        vpcs = ec2.describe_vpcs().get("Vpcs", [])
        non_default = [v for v in vpcs if not v.get("IsDefault", False)]
        if non_default:
            findings["Custom VPCs"] = [
                {"ID": v["VpcId"], "CIDR": v["CidrBlock"]}
                for v in non_default
            ]
    except Exception:
        pass

    # CloudFront (us-east-1 only)
    if region == "us-east-1":
        try:
            cf = sess.client("cloudfront")
            dists = cf.list_distributions().get("DistributionList", {})
            items_list = dists.get("Items", [])
            if items_list:
                findings["CloudFront Distributions"] = [
                    {"ID": d["Id"], "Domain": d.get("DomainName", ""),
                     "Status": d.get("Status", "")}
                    for d in items_list
                ]
        except Exception:
            pass

    # ECS Clusters
    try:
        ecs = sess.client("ecs")
        clusters = ecs.list_clusters().get("clusterArns", [])
        if clusters:
            findings["ECS Clusters"] = [
                {"ARN": c, "Name": c.split("/")[-1]} for c in clusters
            ]
    except Exception:
        pass

    # ElastiCache
    try:
        ec_client = sess.client("elasticache")
        caches = ec_client.describe_cache_clusters().get("CacheClusters", [])
        if caches:
            findings["ElastiCache Clusters"] = [
                {"ID": c["CacheClusterId"], "Engine": c.get("Engine", ""),
                 "Status": c.get("CacheClusterStatus", "")}
                for c in caches
            ]
    except Exception:
        pass

    # SNS Topics
    try:
        sns = sess.client("sns")
        topics = sns.list_topics().get("Topics", [])
        if topics:
            findings["SNS Topics"] = [
                {"ARN": t["TopicArn"], "Name": t["TopicArn"].split(":")[-1]}
                for t in topics
            ]
    except Exception:
        pass

    # SQS Queues
    try:
        sqs = sess.client("sqs")
        queues = sqs.list_queues().get("QueueUrls", [])
        if queues:
            findings["SQS Queues"] = [
                {"URL": q, "Name": q.split("/")[-1]} for q in queues
            ]
    except Exception:
        pass

    return findings


def get_region_service_tracking(session):
    """Scan all regions in parallel + S3 global."""
    creds = session.get_credentials().get_frozen_credentials()
    session_kwargs = {
        "aws_access_key_id": creds.access_key,
        "aws_secret_access_key": creds.secret_key,
    }
    if creds.token:
        session_kwargs["aws_session_token"] = creds.token

    region_map = {}

    # S3 — global
    try:
        s3 = session.client("s3")
        buckets = s3.list_buckets().get("Buckets", [])
        if buckets:
            for b in buckets:
                loc = "us-east-1"
                try:
                    lr = s3.get_bucket_location(Bucket=b["Name"])
                    loc = lr.get("LocationConstraint") or "us-east-1"
                except Exception:
                    pass
                region_map.setdefault(loc, {})
                region_map[loc].setdefault("S3 Buckets", [])
                region_map[loc]["S3 Buckets"].append({"Name": b["Name"]})
    except Exception:
        pass

    # All regions in parallel
    with ThreadPoolExecutor(max_workers=12) as pool:
        futures = {pool.submit(_scan_region, session_kwargs, r): r for r in ALL_REGIONS}
        for future in as_completed(futures):
            region = futures[future]
            try:
                findings = future.result()
                if findings:
                    region_map.setdefault(region, {})
                    region_map[region].update(findings)
            except Exception:
                pass

    active_regions = {}
    total_resources = 0
    for region, services in sorted(region_map.items()):
        svc_summary = {}
        region_total = 0
        for svc_name, items in services.items():
            svc_summary[svc_name] = len(items)
            region_total += len(items)
        total_resources += region_total
        active_regions[region] = {
            "services": svc_summary,
            "details": services,
            "total_resources": region_total,
            "region_name": REGION_NAMES.get(region, region),
        }

    return {"regions": active_regions, "total_resources": total_resources}


# ═══════════════════════════════════════════════════════════════════════
# STEP 4: Organization Verification
#   - Org ID + Management Account Email must match structure sheet
#   - e.g. info@customerjet.com is in org of om@zenowealth.com
# ═══════════════════════════════════════════════════════════════════════

def get_org_verification(session):
    result = {
        "org_id": "N/A",
        "management_account_id": "N/A",
        "management_account_email": "N/A",
        "org_arn": "N/A",
        "account_name": "N/A",
        "mfa_status": "N/A",
        "iam_user": "N/A",
    }

    try:
        org = session.client("organizations", region_name="us-east-1")
        desc = org.describe_organization()["Organization"]
        result["org_id"] = desc.get("Id", "N/A")
        result["management_account_id"] = desc.get("MasterAccountId", "N/A")
        result["management_account_email"] = desc.get("MasterAccountEmail", "N/A")
        result["org_arn"] = desc.get("Arn", "N/A")
    except Exception as e:
        result["org_id"] = f"Error: {e}"

    try:
        iam = session.client("iam")
        aliases = iam.list_account_aliases().get("AccountAliases", [])
        if aliases:
            result["account_name"] = aliases[0]
    except Exception:
        pass

    try:
        iam = session.client("iam")
        sts = session.client("sts")
        arn = sts.get_caller_identity()["Arn"]
        if ":user/" in arn:
            username = arn.split(":user/")[-1]
            result["iam_user"] = username
            mfa = iam.list_mfa_devices(UserName=username).get("MFADevices", [])
            result["mfa_status"] = "Enabled" if mfa else "Disabled"
        else:
            result["iam_user"] = arn.split("/")[-1]
            result["mfa_status"] = "N/A (not IAM user)"
    except Exception:
        result["mfa_status"] = "Unable to determine"

    return result


# ═══════════════════════════════════════════════════════════════════════
# STEP 5: Service Quotas > Amazon EC2
#   - Running On-Demand Standard (A, C, D, H, I, M, R, T, Z) Instances
#   - Running On-Demand G and VT Instances (if available)
#   - EC2-VPC Elastic IPs
#   For: North Virginia, Mumbai, Hyderabad (if enabled), Singapore (if enabled)
# ═══════════════════════════════════════════════════════════════════════

def get_quota_checks(session):
    EC2_SERVICE_CODE = "ec2"
    QUOTAS = {
        "Running On-Demand Standard (A,C,D,H,I,M,R,T,Z) Instances": "L-1216C47A",
        "Running On-Demand G and VT Instances": "L-DB2BBE81",
        "EC2-VPC Elastic IPs": "L-0263D0A3",
    }

    results = {}

    for region_code, region_name in QUOTA_REGIONS.items():
        sq = session.client("service-quotas", region_name=region_code)
        region_result = {}

        for quota_name, quota_code in QUOTAS.items():
            try:
                resp = sq.get_service_quota(
                    ServiceCode=EC2_SERVICE_CODE, QuotaCode=quota_code,
                )
                q = resp["Quota"]
                region_result[quota_name] = {
                    "value": q["Value"],
                    "unit": q.get("Unit", "None"),
                    "adjustable": q.get("Adjustable", False),
                    "source": "Applied",
                }
            except Exception:
                try:
                    resp = sq.get_aws_default_service_quota(
                        ServiceCode=EC2_SERVICE_CODE, QuotaCode=quota_code,
                    )
                    q = resp["Quota"]
                    region_result[quota_name] = {
                        "value": q["Value"],
                        "unit": q.get("Unit", "None"),
                        "adjustable": q.get("Adjustable", False),
                        "source": "Default",
                    }
                except Exception as e:
                    region_result[quota_name] = {"error": str(e)}

        results[f"{region_name} ({region_code})"] = region_result

    return results


# ═══════════════════════════════════════════════════════════════════════
# STEP-BY-STEP AUDIT GENERATOR (yields live progress)
# Matches the exact 6-step checklist
# ═══════════════════════════════════════════════════════════════════════

def run_audit_steps(access_key, secret_key, account_label="", year=None, month=None):
    session = get_session(access_key, secret_key)

    yield ("connect", "running", f"Connecting to AWS as {account_label}...")
    try:
        identity = get_account_identity(session)
        yield ("connect", "done", identity)
    except Exception as e:
        yield ("connect", "error", str(e))
        return

    audit = {
        "account_label": account_label or identity["account_id"],
        "account_id": identity["account_id"],
        "arn": identity["arn"],
        "audit_timestamp": datetime.utcnow().isoformat() + "Z",
        "billing": None,
        "payment": None,
        "bills": None,
        "regions": None,
        "organization": None,
        "quotas": None,
        "errors": [],
    }

    # Step 1: Billing & Cost Management > Home
    yield ("billing", "running", "Step 1: Billing > Home — Last Month Cost + Forecast...")
    try:
        audit["billing"] = get_billing_analysis(session, year, month)
        yield ("billing", "done", audit["billing"])
    except Exception as e:
        audit["errors"].append(f"Billing: {e}")
        yield ("billing", "error", str(e))

    # Step 2: Billing > Payments — outstanding balance
    yield ("payment", "running", "Step 2: Billing > Payments — Outstanding Balance...")
    try:
        audit["payment"] = get_payment_status(session)
        yield ("payment", "done", audit["payment"])
    except Exception as e:
        audit["errors"].append(f"Payment: {e}")
        yield ("payment", "error", str(e))

    # Step 3a: Billing > Bills — service-by-region cost breakdown
    yield ("bills", "running", "Step 3: Billing > Bills — Service x Region breakdown...")
    try:
        audit["bills"] = get_bills_by_service_region(session, year, month)
        yield ("bills", "done", audit["bills"])
    except Exception as e:
        audit["errors"].append(f"Bills: {e}")
        yield ("bills", "error", str(e))

    # Step 3b: Region & Service scan — every resource
    yield ("regions", "running", "Step 3: Scanning ALL regions for active services...")
    try:
        audit["regions"] = get_region_service_tracking(session)
        yield ("regions", "done", audit["regions"])
    except Exception as e:
        audit["errors"].append(f"Region Tracking: {e}")
        yield ("regions", "error", str(e))

    # Step 4: Organization verification
    yield ("organization", "running", "Step 4: Organizations — verifying Org ID & Mgmt Email...")
    try:
        audit["organization"] = get_org_verification(session)
        yield ("organization", "done", audit["organization"])
    except Exception as e:
        audit["errors"].append(f"Organization: {e}")
        yield ("organization", "error", str(e))

    # Step 5: Service Quotas
    yield ("quotas", "running", "Step 5: Service Quotas — EC2 On-Demand, G&VT, Elastic IPs...")
    try:
        audit["quotas"] = get_quota_checks(session)
        yield ("quotas", "done", audit["quotas"])
    except Exception as e:
        audit["errors"].append(f"Quotas: {e}")
        yield ("quotas", "error", str(e))

    # Step 6: Last Updated
    audit["last_updated"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    yield ("complete", "done", audit)
