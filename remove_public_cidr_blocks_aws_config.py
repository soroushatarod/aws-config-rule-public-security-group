import boto3
import botocore
import json

APPLICABLE_RESOURCES = ["AWS::EC2::SecurityGroup"]
# these security groups will not have their public accessible CIDR blocks removed
SECURITY_GROUPS_ALLOWED_PUBLIC_ACCESS = ["sg-0802d47fff16062080"]
COMPLIANT = "COMPLIANT"
NON_COMPLIANT = "NON_COMPLIANT"
NOT_APPLICABLE = "NOT_APPLICABLE"


def evaluate_compliance(configuration_item):
    if configuration_item["resourceType"] not in APPLICABLE_RESOURCES:
        return {
            "compliance_type": "NOT_APPLICABLE",
            "annotation": "The rule doesn't apply to resources of type " +
                          configuration_item["resourceType"] + "."
        }

    if configuration_item["configurationItemStatus"] == "ResourceDeleted":
        return {
            "compliance_type": "NOT_APPLICABLE",
            "annotation": "The configurationItem was deleted and therefore cannot be validated."
        }

    group_id = configuration_item["configuration"]["groupId"]
    client = boto3.client("ec2");

    try:
        response = client.describe_security_groups(GroupIds=[group_id])
    except botocore.exceptions.ClientError as e:
        return {
            "compliance_type": NON_COMPLIANT,
            "annotation": "describe_security_groups failure on group " + group_id
        }

    protocol_all = False

    compliance_type = COMPLIANT
    annotation_message = "Permissions are correct"

    if group_id not in SECURITY_GROUPS_ALLOWED_PUBLIC_ACCESS:
        # lets find public accessible CIDR Blocks
        for security_group_rule in response["SecurityGroups"][0]["IpPermissions"]:

            # if the rule is all protocol, FromPort is missing
            if "FromPort" not in security_group_rule:
                protocol_all = True

            for sgName, val in security_group_rule.items():
                if sgName == "IpRanges":
                    for r in val:
                        if r["CidrIp"] in ["0.0.0.0/0", "::/0"]:
                            print("Found Non Compliant Security Group: GroupID ", group_id)
                            if not protocol_all:
                                result = client.revoke_security_group_ingress(GroupId=group_id,
                                                                              IpProtocol=security_group_rule[
                                                                                  "IpProtocol"],
                                                                              CidrIp=r["CidrIp"],
                                                                              FromPort=security_group_rule["FromPort"],
                                                                              ToPort=security_group_rule["ToPort"])
                            else:
                                result = client.revoke_security_group_ingress(GroupId=group_id,
                                                                              IpProtocol=security_group_rule[
                                                                                  "IpProtocol"],
                                                                              CidrIp=r["CidrIp"])

                            if result:
                                compliance_type = COMPLIANT
                            else:
                                compliance_type = NON_COMPLIANT
                            print("Result: ", compliance_type)
                            annotation_message = "Permissions were modified"
                        else:
                            compliance_type = COMPLIANT
                            annotation_message = "Permissions are correct"

    return {
        "compliance_type": compliance_type,
        "annotation": annotation_message
    }


def lambda_handler(event, context):
    print(event)

    invoking_event = json.loads(event['invokingEvent'])
    configuration_item = invoking_event["configurationItem"]

    evaluation = evaluate_compliance(configuration_item)

    config = boto3.client('config')

    # the call to put_evalations is required to inform aws config about the changes
    response = config.put_evaluations(
        Evaluations=[
            {
                'ComplianceResourceType': invoking_event['configurationItem']['resourceType'],
                'ComplianceResourceId': invoking_event['configurationItem']['resourceId'],
                'ComplianceType': evaluation["compliance_type"],
                "Annotation": evaluation["annotation"],
                'OrderingTimestamp': invoking_event['configurationItem']['configurationItemCaptureTime']
            },
        ],
        ResultToken=event['resultToken'])
