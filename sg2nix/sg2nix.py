import argparse
import sys
import os
import boto3
from jinja2 import Environment, PackageLoader
from configparser import ConfigParser

# Stolened from nixops :p
def fetch_aws_secret_key(access_key_id):
    """
        Fetch the secret access key corresponding to the given access key ID from ~/.ec2-keys,
        or from ~/.aws/credentials, or from the environment (in that priority).
    """

    def parse_ec2_keys():
        path = os.path.expanduser("~/.ec2-keys")
        if os.path.isfile(path):
            with open(path, 'r') as f:
                contents = f.read()
                for l in contents.splitlines():
                    l = l.split("#")[0] # drop comments
                    w = l.split()
                    if len(w) < 2 or len(w) > 3: continue
                    if len(w) == 3 and w[2] == access_key_id: return (w[0], w[1])
                    if w[0] == access_key_id: return (access_key_id, w[1])
        return None

    def parse_aws_credentials():
        path = os.getenv('AWS_SHARED_CREDENTIALS_FILE', "~/.aws/credentials")
        if not os.path.exists(os.path.expanduser(path)):
            return None

        conf = os.path.expanduser(path)
        config = ConfigParser()
        config.read(conf)
        if access_key_id == config.get('default', 'aws_access_key_id'):
            return (access_key_id, conf.get('default', 'aws_secret_access_key'))
        return (config.get(access_key_id, 'aws_access_key_id'),
                config.get(access_key_id, 'aws_secret_access_key'))

    def ec2_keys_from_env():
        return (access_key_id,
                os.environ.get('EC2_SECRET_KEY') or os.environ.get('AWS_SECRET_ACCESS_KEY'))

    sources = (get_credentials() for get_credentials in
                [parse_ec2_keys, parse_aws_credentials, ec2_keys_from_env])
    # Get the first existing access-secret key pair
    credentials = next( (keys for keys in sources if keys and keys[1]), None)

    if not credentials:
        raise Exception("please set $EC2_SECRET_KEY or $AWS_SECRET_ACCESS_KEY, or add the key for ‘{0}’ to ~/.ec2-keys or ~/.aws/credentials"
                        .format(access_key_id))

    return credentials

def connect_ec2_boto3(region, access_key_id):
    assert region
    (access_key_id, secret_access_key) = fetch_aws_secret_key(access_key_id)
    client = boto3.session.Session().client('ec2', region_name=region, aws_access_key_id=access_key_id, aws_secret_access_key=secret_access_key)
    return client
     
def getsg(securityGroups, region, access_key_id):
    client = connect_ec2_boto3(region, access_key_id)
    # add a try block
    filters = [{ 'Name': 'group-name', 'Values': securityGroups}]
    return client.describe_security_groups(Filters=filters)['SecurityGroups']

def jinja2file(output, file):
    if os.path.isfile(file):
        print("'{}' already exist, rewriting".format(os.path.abspath(file)))
    f = open(file, "w+")
    f.write(output)
    f.close()

def convert2nix(securityGroups, region, output, access_key_id):
    # add a try catch block for wrong sg
    res = getsg(securityGroups, region, access_key_id)
    if res == []:
        print("Security groups not found: Exiting ...")
        sys.exit(1)
    
    # jinja stuff
    file_loader = PackageLoader('sg2nix', 'templates')
    env = Environment(loader=file_loader)
    sg_expressions = env.get_template('sg.nix.j2')
    resource = env.get_template('resource.nix.j2')
    resource_output = []

    # Parsing the SG
    for i in range(0,len(securityGroups)):
        sg = res[i]
        sg_name = sg['GroupName']
        sg_description = sg['Description']
        if 'Tags' in sg:
            sg_tags = sg['Tags'] 
        else:
            sg_tags = []
        sg_vpc = sg['VpcId']
        # wont need id I think
        sg_groupID = sg['GroupId']

        sg_rules = []
        for permissions in sg['IpPermissions']:

            if 'FromPort' in permissions:
                sg_rules_fromport = permissions['FromPort']
            if 'ToPort' in permissions:
                sg_rules_toport = permissions['ToPort']
            
            sg_rules_protocol = permissions['IpProtocol']
            if permissions['IpRanges'] != []:
                for rule in permissions['IpRanges']:
                    if 'Description' in rule:
                        des = rule['Description'] 
                    else:
                        des = "No Description for the rule"
                    if sg_rules_protocol == '-1':
                        sg_rule = """\n        # {}
        {{ protocol = {}; sourceIp = "{}"; }};""".format(des, sg_rules_protocol, rule['CidrIp'])
                    else:
                        sg_rule = """\n        # {}
        {{ fromPort = {}; toPort = {}; protocol = "{}"; sourceIp = "{}"; }};""".format(des, sg_rules_fromport, sg_rules_toport, sg_rules_protocol, rule['CidrIp'])
                    sg_rules.append(sg_rule)
            
            # need to test the actuall expression on nix cause i m not sure how it works in nix
            if permissions['UserIdGroupPairs'] != []:
                for rule in permissions['UserIdGroupPairs']:
                    if 'Description' in rule:
                        des = rule['Description'] 
                    else:
                        des = "No Description for the rule"
                    if sg_rules_protocol == '-1':
                        sg_rule = """\n        # {}
        {{ protocol = {}; sourceGroup.ownerId = "{}"; sourceGroup.groupName = "{}"; }};""".format(des, sg_rules_protocol, rule['UserId'], rule['UserIdGroupId'])
                    else:
                        sg_rule = """\n        # {}
        {{ fromPort = {}; toPort = {}; protocol = "{}"; sourceGroup.ownerId = "{}"; sourceGroup.groupName = "{}"; }};""".format(des, sg_rules_fromport, sg_rules_toport, sg_rules_protocol, rule['UserId'], rule['GroupId'])
                    sg_rules.append(sg_rule)
            # sg_rules_typenumber = permissions['FromPort'] ??
            # sg_rules_codeNumber = "" ????? 
        resource_output.append(resource.render(resource_name=sg_name, vpcId=sg_vpc, description=sg_description,
                                            name=sg_name, rules = sg_rules, tags = sg_tags))

    sg_output = sg_expressions.render(region=region, access_key_id=access_key_id, resources=resource_output)
    
    jinja2file(sg_output, output)

def main():

    parser = argparse.ArgumentParser(description='Convert existing AWS security groups to nix files')

    parser.add_argument( '-r', '--region', dest='region', metavar='region',
                        required=True, help='Security Groups region')
    parser.add_argument( '-s', '--securityGroups', dest='securityGroups', metavar='security-groups', required=True,
                        action='append', help='List of security groups to convert')
    parser.add_argument( '-o', '--output', dest='output', metavar='output', required=False,
                        help='Files where the nix expressions will be written')
    parser.add_argument( '-i', '--access_key_id', dest='access_key_id', metavar='access_key_id', required=False,
                        help='AWS access_key_id', default="default")
    args = parser.parse_args()

    output = args.output
    region = args.region
    access_key_id =args.access_key_id
    securityGroups = args.securityGroups

    convert2nix(securityGroups, region, output, access_key_id)
if __name__ == '__main__':

    main()

    # donno if we can use egress rules in nixops, skipping that
