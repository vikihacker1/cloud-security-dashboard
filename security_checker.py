import boto3
from datetime import datetime, timedelta
import pytz # Import the new library

def check_s3_buckets():
    """Checks for S3 buckets that might be public."""
    s3 = boto3.client('s3')
    findings = []
    try:
        buckets = s3.list_buckets()['Buckets']
        for bucket in buckets:
            bucket_name = bucket['Name']
            try:
                pab_config = s3.get_public_access_block(Bucket=bucket_name)['PublicAccessBlockConfiguration']
                if not all([pab_config['BlockPublicAcls'], pab_config['BlockPublicPolicy'], pab_config['IgnorePublicAcls'], pab_config['RestrictPublicBuckets']]):
                    findings.append({'text': f"S3 Bucket '{bucket_name}' has weak Public Access Block settings.", 'severity': 'High'})
            except s3.exceptions.ClientError:
                findings.append({'text': f"S3 Bucket '{bucket_name}' has NO Public Access Block.", 'severity': 'Critical'})
    except Exception as e:
        print(f"An error occurred during S3 check: {e}")
    return findings

def check_root_mfa():
    """Checks if the AWS account's root user has MFA enabled."""
    iam = boto3.client('iam')
    findings = []
    try:
        summary = iam.get_account_summary()
        if summary['SummaryMap']['AccountMFAEnabled'] == 0:
            findings.append({'text': "MFA is not enabled for the root account.", 'severity': 'Critical'})
    except Exception as e:
        findings.append({'text': f"Error checking root MFA: {e}", 'severity': 'Info'})
    return findings
    
def check_iam_users_mfa():
    """Finds IAM users who do not have an MFA device configured."""
    iam = boto3.client('iam')
    findings = []
    try:
        users = iam.list_users()['Users']
        for user in users:
            username = user['UserName']
            mfa_devices = iam.list_mfa_devices(UserName=username)['MFADevices']
            if not mfa_devices:
                findings.append({'text': f"IAM User '{username}' does not have MFA enabled.", 'severity': 'Medium'})
    except Exception as e:
        findings.append({'text': f"Error checking IAM user MFA: {e}", 'severity': 'Info'})
    return findings    

def check_old_access_keys():
    """Finds IAM access keys older than 90 days."""
    iam = boto3.client('iam')
    findings = []
    ninety_days_ago = datetime.now(pytz.utc) - timedelta(days=90)
    try:
        users = iam.list_users()['Users']
        for user in users:
            username = user['UserName']
            keys = iam.list_access_keys(UserName=username)['AccessKeyMetadata']
            for key in keys:
                if key['Status'] == 'Active':
                    create_date = key['CreateDate']
                    if create_date < ninety_days_ago:
                        findings.append({'text': f"User '{username}' has an active access key older than 90 days.", 'severity': 'Medium'})
    except Exception as e:
        findings.append({'text': f"Error checking old access keys: {e}", 'severity': 'Info'})
    return findings

def check_risky_security_groups():
    """Checks for security groups with risky rules (e.g., ports 22, 3389 open to 0.0.0.0/0)."""
    ec2 = boto3.client('ec2')
    findings = []
    risky_ports = [22, 3389]
    try:
        sgs = ec2.describe_security_groups()['SecurityGroups']
        for sg in sgs:
            for perm in sg['IpPermissions']:
                for ip_range in perm.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        if 'FromPort' in perm and perm['FromPort'] in risky_ports:
                            port = perm['FromPort']
                            findings.append({'text': f"Security Group '{sg['GroupName']}' has port {port} open to the world (0.0.0.0/0).", 'severity': 'High'})
    except Exception as e:
        findings.append({'text': f"Error checking security groups: {e}", 'severity': 'Info'})
    return findings