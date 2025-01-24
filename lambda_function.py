import requests
import boto3
import logging

# Pass SNS ARN here
sns_arn = "arn:aws:sns:ap-south-1:979596463358:MC-API-Monitor"

# Pass dummy URLs here
urls = [
    "http://httpbin.org/basic-auth/user/passwd",  # Simulates a basic auth page
    "https://httpstat.us/401"  # Always returns 401 Unauthorized
]

# Initialize AWS SNS client
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
                log_messages.append(f"{url}: Sign-in page detected (401 Unauthorized).\n")
            else:
                down_urls.append(f"{url}: Unexpected status code {response.status_code}.")
                log_messages.append(f"{url}: Unexpected status code {response.status_code}.\n")
        except requests.exceptions.RequestException as e:
            down_urls.append(f"{url}: Error encountered: {e}")
            log_messages.append(f"{url}: Error encountered: {e}\n")
        except Exception as e:
            down_urls.append(f"{url}: Unexpected error: {e}")
            log_messages.append(f"{url}: Unexpected error: {e}\n")

    # Send logs and alerts if necessary
    try:
        if down_urls:
            alert_message = "The following URLs are down:\n" + "\n".join(down_urls)
            send_message(alert_message, "URL Monitoring Alert")
            logger.info("Alert with logs sent to SNS.\n")
        else:
            send_message("\n".join(log_messages), "URL Monitoring Logs")
            logger.info("Logs sent to SNS.\n")
    except Exception as e:
        logger.error(f"Failed to send message to SNS: {e}")

def send_message(message, subject):
    sns_client.publish(
        TopicArn=sns_arn,
        Subject=subject,
        Message=message
    )
