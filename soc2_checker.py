# soc2_checker.py
import boto3
import json
import argparse
import sys
import requests
from botocore.exceptions import ClientError
import os

# ========== Utility Functions ==========
def print_status(service, control, status, details, results):
    results.append({
        'Service': service,
        'Control': control,
        'Status': status,
        'Details': details
    })

def paginate(client, func, key, **kwargs):
    paginator = client.get_paginator(func)
    for page in paginator.paginate(**kwargs):
        for item in page.get(key, []):
            yield item

# ========== IAM & Security ==========
def check_iam_security(results):
    client = boto3.client('iam')
    # MFA enabled for all users
    try:
        users = client.list_users()['Users']
        for user in users:
            mfa = client.list_mfa_devices(UserName=user['UserName'])['MFADevices']
            if not mfa:
                print_status('IAM', 'MFA enabled for all users', 'Fail', f"User {user['UserName']} has no MFA device", results)
            else:
                print_status('IAM', 'MFA enabled for all users', 'Pass', f"User {user['UserName']} has MFA device(s)", results)
    except Exception as e:
        print_status('IAM', 'MFA enabled for all users', 'Fail', f"Error: {e}", results)
    # Least privilege for roles/policies
    try:
        roles = client.list_roles()['Roles']
        for role in roles:
            attached = client.list_attached_role_policies(RoleName=role['RoleName'])['AttachedPolicies']
            for policy in attached:
                policy_arn = policy['PolicyArn']
                policy_ver = client.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
                policy_doc = client.get_policy_version(PolicyArn=policy_arn, VersionId=policy_ver)['PolicyVersion']['Document']
                statements = policy_doc.get('Statement', [])
                if not isinstance(statements, list):
                    statements = [statements]
                for stmt in statements:
                    effect = stmt.get('Effect')
                    action = stmt.get('Action')
                    resource = stmt.get('Resource')
                    if effect == 'Allow' and (action == '*' or resource == '*'):
                        print_status('IAM', 'Least privilege for roles', 'Fail', f"Role {role['RoleName']} has overly broad policy {policy_arn}", results)
                    else:
                        print_status('IAM', 'Least privilege for roles', 'Pass', f"Role {role['RoleName']} policy {policy_arn} is scoped", results)
    except Exception as e:
        print_status('IAM', 'Least privilege for roles', 'Fail', f"Error: {e}", results)

# ========== CloudFront ==========
def check_cloudfront(results):
    client = boto3.client('cloudfront')
    try:
        dists = client.list_distributions().get('DistributionList', {}).get('Items', [])
        for dist in dists:
            # TLS 1.2+
            min_proto = dist['ViewerCertificate'].get('MinimumProtocolVersion', '')
            if min_proto >= 'TLSv1.2_2021':
                print_status('CloudFront', 'TLS 1.2+ enforced', 'Pass', f"Distribution {dist['Id']} uses {min_proto}", results)
            else:
                print_status('CloudFront', 'TLS 1.2+ enforced', 'Fail', f"Distribution {dist['Id']} uses {min_proto}", results)
            # WAF attached
            waf = dist.get('WebACLId')
            if waf:
                print_status('CloudFront', 'WAF attached', 'Pass', f"Distribution {dist['Id']} has WAF {waf}", results)
            else:
                print_status('CloudFront', 'WAF attached', 'Fail', f"Distribution {dist['Id']} has no WAF", results)
    except Exception as e:
        print_status('CloudFront', 'General', 'Fail', f"Error: {e}", results)

# ========== API Gateway ==========
def check_apigateway(results):
    client = boto3.client('apigateway')
    try:
        apis = client.get_rest_apis()['items']
        for api in apis:
            # Logging
            stages = client.get_stages(restApiId=api['id'])['item']
            for stage in stages:
                logging = stage.get('methodSettings', {})
                if any(ms.get('loggingLevel') in ['INFO', 'ERROR'] for ms in logging.values()):
                    print_status('API Gateway', 'Logging enabled', 'Pass', f"API {api['name']} stage {stage['stageName']} logging enabled", results)
                else:
                    print_status('API Gateway', 'Logging enabled', 'Fail', f"API {api['name']} stage {stage['stageName']} logging not enabled", results)
                # Throttling & request validation
                if any(ms.get('throttlingBurstLimit') or ms.get('throttlingRateLimit') for ms in logging.values()):
                    print_status('API Gateway', 'Throttling configured', 'Pass', f"API {api['name']} stage {stage['stageName']} throttling set", results)
                else:
                    print_status('API Gateway', 'Throttling configured', 'Fail', f"API {api['name']} stage {stage['stageName']} throttling not set", results)
                if any(ms.get('dataTraceEnabled') for ms in logging.values()):
                    print_status('API Gateway', 'Request validation', 'Pass', f"API {api['name']} stage {stage['stageName']} request validation enabled", results)
                else:
                    print_status('API Gateway', 'Request validation', 'Fail', f"API {api['name']} stage {stage['stageName']} request validation not enabled", results)
    except Exception as e:
        print_status('API Gateway', 'General', 'Fail', f"Error: {e}", results)

# ========== NLB ==========
def check_nlb(results):
    client = boto3.client('elbv2')
    try:
        lbs = client.describe_load_balancers()['LoadBalancers']
        for lb in lbs:
            if lb['Type'] != 'network':
                continue
            # Ports
            listeners = client.describe_listeners(LoadBalancerArn=lb['LoadBalancerArn'])['Listeners']
            open_ports = [l['Port'] for l in listeners]
            if all(p in [80, 443] for p in open_ports):
                print_status('NLB', 'Only required ports open', 'Pass', f"NLB {lb['LoadBalancerName']} ports: {open_ports}", results)
            else:
                print_status('NLB', 'Only required ports open', 'Fail', f"NLB {lb['LoadBalancerName']} ports: {open_ports}", results)
            # Security Groups
            sgs = lb.get('SecurityGroups', [])
            if sgs:
                ec2 = boto3.client('ec2')
                for sg in sgs:
                    sg_desc = ec2.describe_security_groups(GroupIds=[sg])['SecurityGroups'][0]
                    for perm in sg_desc['IpPermissions']:
                        if perm.get('IpRanges'):
                            for ipr in perm['IpRanges']:
                                if ipr.get('CidrIp') == '0.0.0.0/0':
                                    print_status('NLB', 'SGs are restrictive', 'Fail', f"NLB {lb['LoadBalancerName']} SG {sg} open to world", results)
                                    break
                    else:
                        print_status('NLB', 'SGs are restrictive', 'Pass', f"NLB {lb['LoadBalancerName']} SG {sg} is restrictive", results)
            else:
                print_status('NLB', 'SGs are restrictive', 'Fail', f"NLB {lb['LoadBalancerName']} has no SGs", results)
    except Exception as e:
        print_status('NLB', 'General', 'Fail', f"Error: {e}", results)

# ========== ECS/ECR ==========
def check_ecs_ecr(results):
    ecs = boto3.client('ecs')
    ecr = boto3.client('ecr')
    sm = boto3.client('secretsmanager')
    ssm = boto3.client('ssm')
    # ECS tasks
    try:
        clusters = ecs.list_clusters()['clusterArns']
        for cluster in clusters:
            tasks = ecs.list_task_definitions(familyPrefix='', status='ACTIVE')['taskDefinitionArns']
            for td_arn in tasks:
                td = ecs.describe_task_definition(taskDefinition=td_arn)['taskDefinition']
                for container in td.get('containerDefinitions', []):
                    image = container.get('image', '')
                    if ":latest" in image:
                        print_status('ECS/ECR', 'No images tagged latest', 'Fail', f"Task {td_arn} uses image {image}", results)
                    else:
                        print_status('ECS/ECR', 'No images tagged latest', 'Pass', f"Task {td_arn} uses image {image}", results)
                    # Secrets
                    secrets = container.get('secrets', [])
                    if secrets:
                        print_status('ECS/ECR', 'Secrets from Secrets Manager/SSM', 'Pass', f"Task {td_arn} pulls secrets", results)
                    else:
                        print_status('ECS/ECR', 'Secrets from Secrets Manager/SSM', 'Fail', f"Task {td_arn} may have hardcoded secrets", results)
    except Exception as e:
        print_status('ECS/ECR', 'General', 'Fail', f"Error: {e}", results)
    # ECR image scanning
    try:
        repos = ecr.describe_repositories()['repositories']
        for repo in repos:
            scan = repo.get('imageScanningConfiguration', {}).get('scanOnPush', False)
            if scan:
                print_status('ECS/ECR', 'ECR image scanning enabled', 'Pass', f"Repo {repo['repositoryName']} scanOnPush enabled", results)
            else:
                print_status('ECS/ECR', 'ECR image scanning enabled', 'Fail', f"Repo {repo['repositoryName']} scanOnPush disabled", results)
    except Exception as e:
        print_status('ECS/ECR', 'ECR image scanning enabled', 'Fail', f"Error: {e}", results)

# ========== S3 ==========
def check_s3(results):
    s3 = boto3.client('s3')
    try:
        buckets = s3.list_buckets()['Buckets']
        for bucket in buckets:
            name = bucket['Name']
            # Block Public Access
            try:
                bpa = s3.get_public_access_block(Bucket=name)['PublicAccessBlockConfiguration']
                if all(bpa.values()):
                    print_status('S3', 'Block Public Access enabled', 'Pass', f"Bucket {name} BPA enabled", results)
                else:
                    print_status('S3', 'Block Public Access enabled', 'Fail', f"Bucket {name} BPA not fully enabled", results)
            except ClientError as e:
                print_status('S3', 'Block Public Access enabled', 'Fail', f"Bucket {name} BPA error: {e}", results)
            # Default encryption
            try:
                enc = s3.get_bucket_encryption(Bucket=name)
                rules = enc['ServerSideEncryptionConfiguration']['Rules']
                if any(r['ApplyServerSideEncryptionByDefault']['SSEAlgorithm'] == 'aws:kms' for r in rules):
                    print_status('S3', 'Default encryption SSE-KMS', 'Pass', f"Bucket {name} uses SSE-KMS", results)
                else:
                    print_status('S3', 'Default encryption SSE-KMS', 'Fail', f"Bucket {name} does not use SSE-KMS", results)
            except ClientError as e:
                print_status('S3', 'Default encryption SSE-KMS', 'Fail', f"Bucket {name} encryption error: {e}", results)
            # Bucket policy
            try:
                pol = s3.get_bucket_policy(Bucket=name)
                policy = json.loads(pol['Policy'])
                for stmt in policy.get('Statement', []):
                    if stmt.get('Effect') == 'Allow' and stmt.get('Principal') == '*':
                        print_status('S3', 'No broad bucket principals', 'Fail', f"Bucket {name} has broad principal", results)
                        break
                else:
                    print_status('S3', 'No broad bucket principals', 'Pass', f"Bucket {name} has no broad principal", results)
            except ClientError as e:
                if 'NoSuchBucketPolicy' in str(e):
                    print_status('S3', 'No broad bucket principals', 'Pass', f"Bucket {name} has no policy", results)
                else:
                    print_status('S3', 'No broad bucket principals', 'Fail', f"Bucket {name} policy error: {e}", results)
    except Exception as e:
        print_status('S3', 'General', 'Fail', f"Error: {e}", results)

# ========== MongoDB Atlas ==========
def check_mongodb_atlas(results, atlas_public_key, atlas_private_key, project_id):
    # Atlas API base
    base = 'https://cloud.mongodb.com/api/atlas/v1.0'
    session = requests.Session()
    session.auth = (atlas_public_key, atlas_private_key)
    # TLS
    try:
        url = f"{base}/groups/{project_id}/clusters"
        resp = session.get(url)
        resp.raise_for_status()
        clusters = resp.json().get('results', [])
        for cluster in clusters:
            if cluster.get('sslEnabled', True):
                print_status('MongoDB Atlas', 'TLS enabled', 'Pass', f"Cluster {cluster['name']} TLS enabled", results)
            else:
                print_status('MongoDB Atlas', 'TLS enabled', 'Fail', f"Cluster {cluster['name']} TLS not enabled", results)
            # Encryption at rest
            if cluster.get('encryptionAtRestProvider', ''):
                print_status('MongoDB Atlas', 'Encryption at rest', 'Pass', f"Cluster {cluster['name']} encryption at rest enabled", results)
            else:
                print_status('MongoDB Atlas', 'Encryption at rest', 'Fail', f"Cluster {cluster['name']} encryption at rest not enabled", results)
            # Backups
            if cluster.get('backupEnabled', False):
                print_status('MongoDB Atlas', 'Backups enabled', 'Pass', f"Cluster {cluster['name']} backups enabled", results)
            else:
                print_status('MongoDB Atlas', 'Backups enabled', 'Fail', f"Cluster {cluster['name']} backups not enabled", results)
        # IP allowlist
        url = f"{base}/groups/{project_id}/accessList"
        resp = session.get(url)
        resp.raise_for_status()
        ips = resp.json().get('results', [])
        if ips:
            print_status('MongoDB Atlas', 'IP allowlist in place', 'Pass', f"Project {project_id} has IP allowlist", results)
        else:
            print_status('MongoDB Atlas', 'IP allowlist in place', 'Fail', f"Project {project_id} has no IP allowlist", results)
    except Exception as e:
        print_status('MongoDB Atlas', 'General', 'Fail', f"Error: {e}", results)

# ========== CloudWatch ==========
def check_cloudwatch(results):
    client = boto3.client('logs')
    cw = boto3.client('cloudwatch')
    try:
        # Log group retention
        groups = client.describe_log_groups()['logGroups']
        for group in groups:
            if group.get('retentionInDays'):
                print_status('CloudWatch', 'Log group retention', 'Pass', f"Log group {group['logGroupName']} retention {group['retentionInDays']} days", results)
            else:
                print_status('CloudWatch', 'Log group retention', 'Fail', f"Log group {group['logGroupName']} has no retention policy", results)
        # Alarms for ECS, NLB, API Gateway
        alarms = cw.describe_alarms()['MetricAlarms']
        for service in ['ECS', 'NLB', 'API Gateway']:
            found = any(service in alarm['AlarmName'] for alarm in alarms)
            if found:
                print_status('CloudWatch', f'Alarms for {service}', 'Pass', f"Alarm for {service} exists", results)
            else:
                print_status('CloudWatch', f'Alarms for {service}', 'Fail', f"No alarm for {service}", results)
    except Exception as e:
        print_status('CloudWatch', 'General', 'Fail', f"Error: {e}", results)

# ========== Main ==========
def write_html_report(results, output_file):
    # Group by service and count pass/fail
    from collections import defaultdict, Counter
    service_groups = defaultdict(list)
    pass_count = 0
    fail_count = 0
    for r in results:
        service_groups[r['Service']].append(r)
        if r['Status'].lower() == 'pass':
            pass_count += 1
        else:
            fail_count += 1

    # Per-service summary
    service_summary = {}
    for service, items in service_groups.items():
        c = Counter([i['Status'].lower() for i in items])
        service_summary[service] = {'pass': c.get('pass', 0), 'fail': c.get('fail', 0), 'total': len(items)}

        html = '''
<html>
<head>
<meta charset="UTF-8">
<title>SOC 2 AWS Readiness Report</title>
<style>
body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #f4f6fa; margin: 0; padding: 0; }}
.container {{ max-width: 1100px; margin: 40px auto; background: #fff; border-radius: 10px; box-shadow: 0 2px 8px #0001; padding: 32px; }}
h1 {{ text-align: center; color: #2d3a4a; }}
table {{ border-collapse: collapse; width: 100%; margin-top: 24px; }}
th, td {{ padding: 12px 16px; text-align: left; }}
th {{ background: #2d3a4a; color: #fff; position: sticky; top: 0; }}
tr {{ transition: background 0.2s; }}
tr:hover {{ background: #eaf1fb; }}
.pass {{ color: #1a7f37; font-weight: bold; }}
.fail {{ color: #d7263d; font-weight: bold; }}
.filter-bar {{ margin-bottom: 18px; }}
.filter-bar label {{ margin-right: 10px; }}
.status-dot {{ display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 6px; }}
.pass-dot {{ background: #1a7f37; }}
.fail-dot {{ background: #d7263d; }}
.summary-table {{ margin-bottom: 32px; }}
.service-group {{ margin-top: 36px; }}
.service-title {{ font-size: 1.2em; margin: 18px 0 8px 0; color: #2d3a4a; }}
</style>
<script>
function filterTable() {{
    var input = document.getElementById('serviceFilter').value.toLowerCase();
    var groups = document.querySelectorAll('.service-group');
    groups.forEach(function(group) {{
        var service = group.getAttribute('data-service').toLowerCase();
        group.style.display = service.includes(input) ? '' : 'none';
    }});
}}
</script>
</head>
<body>
<div class="container">
<h1>SOC 2 AWS Readiness Report</h1>
<div class="filter-bar">
    <label for="serviceFilter">Filter by Service:</label>
    <input type="text" id="serviceFilter" onkeyup="filterTable()" placeholder="e.g. S3, IAM, CloudFront...">
</div>

<table class="summary-table">
<thead><tr><th>Total Checks</th><th>Pass</th><th>Fail</th></tr></thead>
<tbody>
<tr><td>{total}</td><td class="pass">{passed}</td><td class="fail">{failed}</td></tr>
</tbody>
</table>

<table class="summary-table">
<thead><tr><th>Service</th><th>Pass</th><th>Fail</th><th>Total</th></tr></thead>
<tbody>
'''.format(total=pass_count+fail_count, passed=pass_count, failed=fail_count)
    for service, summ in service_summary.items():
        html += f'<tr><td>{service}</td><td class="pass">{summ["pass"]}</td><td class="fail">{summ["fail"]}</td><td>{summ["total"]}</td></tr>\n'
    html += '''
</tbody>
</table>
'''
    # Grouped details by service
    for service, items in service_groups.items():
        html += f'<div class="service-group" data-service="{service}">\n'
        html += f'<div class="service-title">{service}</div>\n'
        html += '''<table><thead><tr><th>Control</th><th>Status</th><th>Details</th></tr></thead><tbody>'''
        for r in items:
            status_class = 'pass' if r['Status'].lower() == 'pass' else 'fail'
            dot = '<span class="status-dot pass-dot"></span>' if status_class == 'pass' else '<span class="status-dot fail-dot"></span>'
            html += f"<tr><td>{r['Control']}</td><td class='{status_class}'>{dot}{r['Status']}</td><td>{r['Details']}</td></tr>\n"
        html += '</tbody></table></div>\n'
    html += '''
</div>
</body>
</html>
'''
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html)
    print(f"HTML report written to {output_file}")

def main():
    parser = argparse.ArgumentParser(description='SOC 2 AWS Readiness Checker')
    parser.add_argument('--output', help='Output file for report (JSON or HTML)')
    parser.add_argument('--atlas-public-key', help='MongoDB Atlas Public Key')
    parser.add_argument('--atlas-private-key', help='MongoDB Atlas Private Key')
    parser.add_argument('--atlas-project-id', help='MongoDB Atlas Project ID')
    parser.add_argument('--skip-atlas', action='store_true', help='Skip MongoDB Atlas scan')
    parser.add_argument('--profile', help='AWS profile to use (from ~/.aws/credentials)')
    args = parser.parse_args()

    # Set AWS profile if provided
    if args.profile:
        os.environ['AWS_PROFILE'] = args.profile

    results = []
    check_iam_security(results)
    check_cloudfront(results)
    check_apigateway(results)
    check_nlb(results)
    check_ecs_ecr(results)
    check_s3(results)
    if not args.skip_atlas:
        if args.atlas_public_key and args.atlas_private_key and args.atlas_project_id:
            check_mongodb_atlas(results, args.atlas_public_key, args.atlas_private_key, args.atlas_project_id)
        else:
            print_status('MongoDB Atlas', 'General', 'Fail', 'Atlas credentials/project ID not provided', results)
    else:
        print_status('MongoDB Atlas', 'General', 'Pass', 'Atlas scan skipped (--skip-atlas)', results)
    check_cloudwatch(results)

    if args.output:
        ext = os.path.splitext(args.output)[1].lower()
        if ext == '.html':
            write_html_report(results, args.output)
        else:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"Report written to {args.output}")
    else:
        # Print as table
        from tabulate import tabulate
        print(tabulate(results, headers='keys'))

if __name__ == '__main__':
    main()
