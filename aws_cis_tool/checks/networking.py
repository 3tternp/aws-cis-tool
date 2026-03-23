from .base import CISCheck
import botocore.exceptions

class Check_5_1(CISCheck):
    def __init__(self, auth_session):
        super().__init__(
            auth_session, 
            check_id="5.1", 
            title="Ensure no security groups allow ingress from 0.0.0.0/0 to port 22", 
            category="Networking", 
            description="Security groups provide stateful filtering of ingress/egress network traffic to AWS resources. Port 22 (SSH) should not be open to the internet."
        )

    def execute(self):
        try:
            ec2 = self.auth.get_client('ec2')
            paginator = ec2.get_paginator('describe_security_groups')
            
            violating_sgs = []
            checked_sgs = 0
            for page in paginator.paginate():
                for sg in page['SecurityGroups']:
                    checked_sgs += 1
                    for perm in sg['IpPermissions']:
                        if perm.get('IpProtocol') in ['tcp', '-1']:
                            from_port = perm.get('FromPort', 0)
                            to_port = perm.get('ToPort', 65535)
                            
                            # Check if port 22 is in range or if protocol is -1 (all)
                            if (from_port <= 22 and to_port >= 22) or perm.get('IpProtocol') == '-1':
                                for ip_range in perm.get('IpRanges', []):
                                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                                        violating_sgs.append(f"{sg['GroupId']} ({sg['GroupName']})")
                                        
            evidence = {"CheckedSecurityGroups": checked_sgs, "ViolatingSecurityGroups": violating_sgs}
            if violating_sgs:
                self.fail_check(f"Security groups allowing SSH from 0.0.0.0/0: {', '.join(violating_sgs)}", evidence=evidence)
            else:
                self.pass_check("No security groups allow SSH from 0.0.0.0/0.", evidence=evidence)
                
        except botocore.exceptions.ClientError as e:
            self.error_check(f"Failed to check security groups: {e}")
        except Exception as e:
            self.error_check(f"Unexpected error: {e}")

class Check_5_2(CISCheck):
    def __init__(self, auth_session):
        super().__init__(
            auth_session, 
            check_id="5.2", 
            title="Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389", 
            category="Networking", 
            description="Port 3389 (RDP) should not be open to the internet."
        )

    def execute(self):
        try:
            ec2 = self.auth.get_client('ec2')
            paginator = ec2.get_paginator('describe_security_groups')
            
            violating_sgs = []
            checked_sgs = 0
            for page in paginator.paginate():
                for sg in page['SecurityGroups']:
                    checked_sgs += 1
                    for perm in sg['IpPermissions']:
                        if perm.get('IpProtocol') in ['tcp', 'udp', '-1']:
                            from_port = perm.get('FromPort', 0)
                            to_port = perm.get('ToPort', 65535)
                            
                            if (from_port <= 3389 and to_port >= 3389) or perm.get('IpProtocol') == '-1':
                                for ip_range in perm.get('IpRanges', []):
                                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                                        violating_sgs.append(f"{sg['GroupId']} ({sg['GroupName']})")
                                        
            evidence = {"CheckedSecurityGroups": checked_sgs, "ViolatingSecurityGroups": violating_sgs}
            if violating_sgs:
                self.fail_check(f"Security groups allowing RDP from 0.0.0.0/0: {', '.join(violating_sgs)}", evidence=evidence)
            else:
                self.pass_check("No security groups allow RDP from 0.0.0.0/0.", evidence=evidence)
                
        except botocore.exceptions.ClientError as e:
            self.error_check(f"Failed to check security groups: {e}")
        except Exception as e:
            self.error_check(f"Unexpected error: {e}")

class Check_5_3(CISCheck):
    def __init__(self, auth_session):
        super().__init__(
            auth_session, 
            check_id="5.3", 
            title="Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports", 
            category="Networking", 
            description="The Network Access Control List (NACL) function provides a stateless filtering method. NACLs should not allow unrestricted ingress access to ports 22 or 3389."
        )

    def execute(self):
        try:
            ec2 = self.auth.get_client('ec2')
            nacls = ec2.describe_network_acls().get('NetworkAcls', [])
            
            violating_nacls = []
            checked_nacls = 0
            
            for nacl in nacls:
                checked_nacls += 1
                for entry in nacl['Entries']:
                    if not entry['Egress'] and entry['RuleAction'] == 'allow' and entry.get('CidrBlock') == '0.0.0.0/0':
                        protocol = entry['Protocol']
                        port_range = entry.get('PortRange', {})
                        
                        if protocol == '-1':
                            violating_nacls.append(f"{nacl['NetworkAclId']} (All Traffic)")
                            break
                        elif protocol == '6':
                            from_port = port_range.get('From', 0)
                            to_port = port_range.get('To', 65535)
                            
                            if (from_port <= 22 and to_port >= 22) or (from_port <= 3389 and to_port >= 3389):
                                violating_nacls.append(f"{nacl['NetworkAclId']} (Ports exposed)")
                                break
            
            evidence = {"CheckedNetworkAcls": checked_nacls, "ViolatingNetworkAcls": violating_nacls}
            if violating_nacls:
                self.fail_check(f"NACLs allowing ingress to 22/3389 from 0.0.0.0/0: {', '.join(violating_nacls)}", evidence=evidence)
            else:
                self.pass_check("No NACLs allow unrestricted ingress to port 22 or 3389.", evidence=evidence)
                
        except botocore.exceptions.ClientError as e:
            self.error_check(f"Failed to check NACLs: {e}")
        except Exception as e:
            self.error_check(f"Unexpected error: {e}")

class Check_5_4(CISCheck):
    def __init__(self, auth_session):
        super().__init__(
            auth_session, 
            check_id="5.4", 
            title="Ensure the default security group of every VPC restricts all traffic", 
            category="Networking", 
            description="The default security group cannot be deleted. It should be configured to restrict all traffic."
        )

    def execute(self):
        try:
            ec2 = self.auth.get_client('ec2')
            vpcs = ec2.describe_vpcs().get('Vpcs', [])
            
            violating_sgs = []
            checked_vpcs = 0
            
            for vpc in vpcs:
                checked_vpcs += 1
                vpc_id = vpc['VpcId']
                sgs = ec2.describe_security_groups(
                    Filters=[
                        {'Name': 'vpc-id', 'Values': [vpc_id]},
                        {'Name': 'group-name', 'Values': ['default']}
                    ]
                ).get('SecurityGroups', [])
                
                for sg in sgs:
                    if sg.get('IpPermissions') or sg.get('IpPermissionsEgress'):
                        violating_sgs.append(f"{sg['GroupId']} (VPC: {vpc_id})")
            
            evidence = {"CheckedVpcs": checked_vpcs, "ViolatingDefaultSecurityGroups": violating_sgs}
            if violating_sgs:
                self.fail_check(f"Default security groups with active rules: {', '.join(violating_sgs)}", evidence=evidence)
            else:
                self.pass_check("All default security groups restrict all traffic (no rules).", evidence=evidence)
                
        except botocore.exceptions.ClientError as e:
            self.error_check(f"Failed to check default security groups: {e}")
        except Exception as e:
            self.error_check(f"Unexpected error: {e}")

class Check_Manual_5_5(CISCheck):
    def __init__(self, auth_session):
        super().__init__(
            auth_session,
            check_id="5.5",
            title="Ensure routing tables for VPC peering are \"least access\"",
            category="Networking",
            description="Routes shared across VPC peers should be limited to only the required destination CIDR ranges.",
            check_type="MANUAL",
            manual_steps=[
                "List all VPC peering connections and identify connected VPCs.",
                "Review each VPC's route tables for routes pointing to a VPC peering connection.",
                "Verify routes via VPC peering use only required destination CIDR blocks (no broad 0.0.0.0/0 or overly large ranges).",
                "Confirm security group and NACL rules also enforce least access for the peered traffic paths."
            ],
            manual_poc=[
                "CLI: aws ec2 describe-vpc-peering-connections --query \"VpcPeeringConnections[].VpcPeeringConnectionId\" --output table",
                "CLI: aws ec2 describe-route-tables --query \"RouteTables[].{RouteTableId:RouteTableId,VpcId:VpcId,PeerRoutes:Routes[?VpcPeeringConnectionId!=null].[DestinationCidrBlock,VpcPeeringConnectionId]}\" --output json",
                "Expected: PeerRoutes only include necessary DestinationCidrBlock values for each peer connection."
            ]
        )

    def execute(self):
        super().execute()

def get_networking_checks(auth_session):
    return [
        Check_5_1(auth_session),
        Check_5_2(auth_session),
        Check_5_3(auth_session),
        Check_5_4(auth_session),
        Check_Manual_5_5(auth_session)
    ]
