# parse-ntsecdesc

## Description

My reason for starting this project was bloodhound sometimes didn't parse the permissions correctly or ignored some of it. <br> 
To address this problem, I developed this tool to parse the ACLs manually to make sure I didn't miss anything.<br>

## Installation

To install this tool you need to install pipx and then simply run:

```
pipx install git+https://github.com/canozsec/parse-ntsecdesc
```

## Usage

You need to get the raw nTSecurityDescriptor and base64 encode it.

```
parse-ntsecdesc -i "Base64 encoded nTSecurityDescriptor"
```

You can get this nTSecurityDescriptor with the required format using [BloodyAD](https://github.com/CravateRouge/bloodyAD):

```
bloodyAD -u $username -p $password --host $DCIP get object 'CN=GROUP1,CN=USERS,DC=SOMEDC,DC=COM' --raw --attr nTSecurityDescriptor
```