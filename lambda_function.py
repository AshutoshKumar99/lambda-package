import requests
import boto3
import logging

# List of URLs to monitor
urls = [
    "https://amer-staging.spectrum.precisely.com/rest/SearchbyEntityID_v1/results.json?Data.ENTITY_ID=285928234&Data.Country=USA",
    "https://mastercard-graph.spectrum.precisely.com/rest/SearchbyEntityID_v1/results.json?Data.ENTITY_ID=285928234&Data.Country=USA",
    "https://mastercard-uat-graph.spectrum.precisely.com/rest/SearchbyEntityID_v1/results.json?Data.ENTITY_ID=285928234&Data.Country=USA",
    "https://amer.spectrum.precisely.com/rest/MC_Match_Search/results.json?Data.Merchant_Name=RADIO SHACK&Data.City=ROCHESTER&Data.State_Province=NY&Data.Postal_Code=146261632&Option.max_results=10"
]

# Replace with the correct ARN for your SNS topic
sns_arn = "arn:aws:sns:ap-south-1:979596463358:MC-API-Monitor"
sns_client = boto3.client('sns')

# Setup logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    log_messages = []
    down_urls = []

    log_messages.append("Lambda function execution started. Checking URLs...\n")

    for url in urls:
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                log_messages.append(f"{url}: Accessible. Status code: 200.\n")
            elif response.status_code == 401:
                log_messages.append(f"{url}: Sign-in page detected.\n")
            else:
                down_urls.append(f"{url}: Unexpected status code {response.status_code}.")
                log_messages.append(f"{url}: Unexpected status code {response.status_code}.\n")
        except requests.exceptions.RequestException as e:
            down_urls.append(f"{url}: Error encountered: {e}")
            log_messages.append(f"{url}: Error encountered: {e}\n")
        except Exception as e:
            down_urls.append(f"{url}: Unexpected error: {e}")
            log_messages.append(f"{url}: Unexpected error: {e}\n")

    # If there are down URLs, send alert and logs
    if down_urls:
        try:
            alert_message = "The following URLs are down:\n" + "\n".join(down_urls)
            send_alert(alert_message, log_messages)  # Send alert and logs
            logger.info("Alert with logs sent to SNS.\n")
        except Exception as e:
            logger.error(f"Failed to send SNS alert with logs: {e}\n")
    else:
        # If no URLs are down, send logs only
        try:
            send_log("\n".join(log_messages))
        except Exception as e:
            logger.error(f"Failed to send logs to SNS: {e}")

def send_alert(alert_message, log_messages):
    # Shorten the alert message for SMS compatibility
    sms_message = alert_message[:140]  # Limit to 140 characters

    # Publish the full message for email and truncated message for SMS
    try:
        subscriptions = sns_client.list_subscriptions_by_topic(TopicArn=sns_arn)['Subscriptions']
        for sub in subscriptions:
            if sub['Protocol'] == 'sms':
                sns_client.publish(
                    PhoneNumber=sub['Endpoint'],
                    Message=sms_message,
                    MessageAttributes={
                        'AWS.SNS.SMS.SMSType': {
                            'DataType': 'String',
                            'StringValue': 'Transactional'
                        }
                    }
                )
            elif sub['Protocol'] == 'email':
                sns_client.publish(
                    TopicArn=sns_arn,
                    Subject="URL Monitoring Alert",
                    Message=alert_message
                )
    except Exception as e:
        logger.error(f"Failed to send alert: {e}")

def send_log(log_message):
    sns_client.publish(
        TopicArn=sns_arn,
        Subject="URL Monitoring Logs",
        Message=log_message
    )
