from .base import CISCheck
import botocore.exceptions

class Check_4_1(CISCheck):
    def __init__(self, auth_session):
        super().__init__(
            auth_session, 
            check_id="4.1", 
            title="Ensure no security groups allow ingress from 0.0.0.0/0 to port 22", 
            category="Networking", 
            description="Security groups provide stateful filtering of ingress/egress network traffic to AWS resources. Port 22 (SSH) should not be open to the internet."
        )

    def execute(self):
        try:
            ec2 = self.auth.get_client('ec2')
            paginator = ec2.get_paginator('describe_security_groups')
            
            violating_sgs = []
            for page in paginator.paginate():
                for sg in page['SecurityGroups']:
                    for perm in sg['IpPermissions']:
                        if perm.get('IpProtocol') in ['tcp', '-1']:
                            from_port = perm.get('FromPort', 0)
                            to_port = perm.get('ToPort', 65535)
                            
                            # Check if port 22 is in range or if protocol is -1 (all)
                            if (from_port <= 22 and to_port >= 22) or perm.get('IpProtocol') == '-1':
                                for ip_range in perm.get('IpRanges', []):
                                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                                        violating_sgs.append(f"{sg['GroupId']} ({sg['GroupName']})")
                                        
            if violating_sgs:
                self.fail_check(f"Security groups allowing SSH from 0.0.0.0/0: {', '.join(violating_sgs)}")
            else:
                self.pass_check("No security groups allow SSH from 0.0.0.0/0.")
                
        except botocore.exceptions.ClientError as e:
            self.error_check(f"Failed to check security groups: {e}")
        except Exception as e:
            self.error_check(f"Unexpected error: {e}")

class Check_4_2(CISCheck):
    def __init__(self, auth_session):
        super().__init__(
            auth_session, 
            check_id="4.2", 
            title="Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389", 
            category="Networking", 
            description="Port 3389 (RDP) should not be open to the internet."
        )

    def execute(self):
        try:
            ec2 = self.auth.get_client('ec2')
            paginator = ec2.get_paginator('describe_security_groups')
            
            violating_sgs = []
            for page in paginator.paginate():
                for sg in page['SecurityGroups']:
                    for perm in sg['IpPermissions']:
                        if perm.get('IpProtocol') in ['tcp', 'udp', '-1']:
                            from_port = perm.get('FromPort', 0)
                            to_port = perm.get('ToPort', 65535)
                            
                            if (from_port <= 3389 and to_port >= 3389) or perm.get('IpProtocol') == '-1':
                                for ip_range in perm.get('IpRanges', []):
                                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                                        violating_sgs.append(f"{sg['GroupId']} ({sg['GroupName']})")
                                        
            if violating_sgs:
                self.fail_check(f"Security groups allowing RDP from 0.0.0.0/0: {', '.join(violating_sgs)}")
            else:
                self.pass_check("No security groups allow RDP from 0.0.0.0/0.")
                
        except botocore.exceptions.ClientError as e:
            self.error_check(f"Failed to check security groups: {e}")
        except Exception as e:
            self.error_check(f"Unexpected error: {e}")

class Check_4_3(CISCheck):
    def __init__(self, auth_session):
        super().__init__(
            auth_session, 
            check_id="4.3", 
            title="Ensure the default security group of every VPC restricts all traffic", 
            category="Networking", 
            description="The default security group cannot be deleted. It should be configured to restrict all traffic."
        )

    def execute(self):
        try:
            ec2 = self.auth.get_client('ec2')
            vpcs = ec2.describe_vpcs().get('Vpcs', [])
            
            violating_sgs = []
            
            for vpc in vpcs:
                vpc_id = vpc['VpcId']
                # Find default SG for this VPC
                sgs = ec2.describe_security_groups(
                    Filters=[
                        {'Name': 'vpc-id', 'Values': [vpc_id]},
                        {'Name': 'group-name', 'Values': ['default']}
                    ]
                ).get('SecurityGroups', [])
                
                for sg in sgs:
                    # Check inbound/outbound rules
                    # A secure default SG should have NO inbound and NO outbound rules (or minimal restricted ones)
                    # CIS says: "inbound and outbound rules should be removed"
                    
                    if sg.get('IpPermissions') or sg.get('IpPermissionsEgress'):
                         violating_sgs.append(f"{sg['GroupId']} (VPC: {vpc_id})")
            
            if violating_sgs:
                self.fail_check(f"Default security groups with active rules: {', '.join(violating_sgs)}")
            else:
                self.pass_check("All default security groups restrict all traffic (no rules).")
                
        except botocore.exceptions.ClientError as e:
            self.error_check(f"Failed to check default security groups: {e}")
        except Exception as e:
            self.error_check(f"Unexpected error: {e}")

class Check_5_1(CISCheck):
    def __init__(self, auth_session):
        super().__init__(
            auth_session, 
            check_id="5.1", 
            title="Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports", 
            category="Networking", 
            description="The Network Access Control List (NACL) function provides a stateless filtering method. NACLs should not allow unrestricted ingress access to ports 22 or 3389."
        )

    def execute(self):
        try:
            ec2 = self.auth.get_client('ec2')
            nacls = ec2.describe_network_acls().get('NetworkAcls', [])
            
            violating_nacls = []
            
            for nacl in nacls:
                for entry in nacl['Entries']:
                    if not entry['Egress'] and entry['RuleAction'] == 'allow' and entry.get('CidrBlock') == '0.0.0.0/0':
                        # Ingress allow from 0.0.0.0/0
                        protocol = entry['Protocol']
                        port_range = entry.get('PortRange', {})
                        
                        # Protocol -1 is all, 6 is TCP, 17 is UDP
                        if protocol == '-1':
                             violating_nacls.append(f"{nacl['NetworkAclId']} (All Traffic)")
                             break
                        elif protocol == '6': # TCP
                            from_port = port_range.get('From', 0)
                            to_port = port_range.get('To', 65535)
                            
                            if (from_port <= 22 and to_port >= 22) or (from_port <= 3389 and to_port >= 3389):
                                violating_nacls.append(f"{nacl['NetworkAclId']} (Ports exposed)")
                                break
            
            if violating_nacls:
                self.fail_check(f"NACLs allowing ingress to 22/3389 from 0.0.0.0/0: {', '.join(violating_nacls)}")
            else:
                self.pass_check("No NACLs allow unrestricted ingress to port 22 or 3389.")
                
        except botocore.exceptions.ClientError as e:
            self.error_check(f"Failed to check NACLs: {e}")
        except Exception as e:
            self.error_check(f"Unexpected error: {e}")

def get_networking_checks(auth_session):
    return [
        Check_4_1(auth_session),
        Check_4_2(auth_session),
        Check_4_3(auth_session),
        Check_5_1(auth_session)
    ]
