# sg2nix
Create nix expressions for existing AWS security groups.

How to setup:

        git clone https://github.com/PsyanticY/sg2nix
        cd sg2nix
        sudo python3 setup.py install


Usage:
```bash
usage: sg2nix [-h] -r region -s security-groups [-o output] [-i access_key_id]

Convert existing AWS security groups to nix files

optional arguments:
  -h, --help            show this help message and exit
  -r region, --region region
                        Security Groups region
  -s security-groups, --securityGroups security-groups
                        List of security groups to convert
  -o output, --output output
                        Files where the nix expressions will be written
  -i access_key_id, --access_key_id access_key_id
                        AWS access_key_id
```
