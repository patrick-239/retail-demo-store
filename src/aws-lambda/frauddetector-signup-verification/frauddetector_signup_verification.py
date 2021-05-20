# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import boto3
import random
import os
import logging

from dataclasses import dataclass

logger = logging.getLogger()
logger.setLevel(logging.INFO)

@dataclass
class AFDRequest:
    email: str
    phone_number: str
    billing_address: str
    billing_postal: str
    billing_state: str
    ip: str
    user_agent: str

def lambda_handler(event, context):
    # It sets the user pool autoConfirmUser flag after validating the email domain
    event['response']['autoConfirmUser'] = False
    
    user_fingerpint_attr = dict()
    for key, value in event['request']['userAttributes'].items():
        # Any other checks of user attributes goes here
        if value == "":
            return event
        if key.startswith("custom"):
            user_fingerpint_attr[key.split(":")[1]] = value
        else:
            user_fingerpint_attr[key] = value
    
    logger.debug(f"received user attributed {user_fingerpint_attr}")
    fraud_request = AFDRequest(**user_fingerpint_attr, ip="1.1.1.1", user_agent="Chrome")

    fraudDetectorClient = boto3.client('frauddetector')
    detectorID = os.environ['fraud_detector_name']
    detectorVersion = os.environ["fraud_detector_version"]
    eventType = os.environ['fraud_detector_event_name']
    
    fraud_request_dict = vars(fraud_request)
    fraud_request_dict["email_address"] = fraud_request_dict.pop("email")
    fraud_request_dict["ip_address"] = fraud_request_dict.pop("ip")
    
    fraudPrediction = fraudDetectorClient.get_event_prediction(
                detectorId=detectorID,
                detectorVersionId=detectorVersion,
                eventId=str(random.randint(100000, 999999)),
                eventTypeName=eventType,
                entities=[
                    {
                        'entityType': "customer",
                        'entityId': event["callerContext"]["clientId"]
                    },
                ],
                eventTimestamp='2020-11-30T14:46:42.453Z',
                eventVariables=fraud_request_dict)
    logger.debug(f"fraud prediction results: {fraudPrediction}")

    isFraud = fraudPrediction["ruleResults"][0]["outcomes"][0] == "high_risk"
    fraud_score = list(fraudPrediction["modelScores"][0]["scores"].values())[0]
    
    if isFraud:
        # Stop sign-up flow, the error will be visiable in Cognito UI form
        raise Exception(f"Cannot authenticate users due to high risk fraud (fraud_score: {fraud_score}), please contact support for more details")
    else:
        # Return to Amazon Cognito
        return event
