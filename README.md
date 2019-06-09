# AWS Config Lambda Code to remove public CIDR Blocks
AWS Config Lambda code which removes public CIDR block rule from security groups

A custom AWS Config rule needs to be created assigned to this Lambda code.

Variables
```
# add the security group IDs which are allowed to have public CIDR Blocks
SECURITY_GROUPS_ALLOWED_PUBLIC_ACCESS = ["sg-0802d47fff16062080"]
```

https://www.infinitypp.com/amazon-aws/writing-custom-aws-config-rules-using-lambda/
