# ![aws](https://github.com/julien-muke/Search-Engine-Website-using-AWS/assets/110755734/01cd6124-8014-4baa-a5fe-bd227844d263) Real-Time Threat Detection on AWS with AI | GuardDuty, CloudTrail, Lambda & SNS 🛡️

<div align="center">

  <br />
    <a href="https://youtu.be/o4fNDCAqyzM" target="_blank">
      <img src="https://github.com/user-attachments/assets/f2592643-7018-4932-8738-495e94505c86" alt="Project Banner">
    </a>
  <br />

<h3 align="center">Build a Real-time AI-powered threat detection and response system on AWS using GuardDuty, SNS, and Lambda. </h3>

   <div align="center">
     Build this hands-on demo step by step with my detailed tutorial on <a href="http://www.youtube.com/@julienmuke/videos" target="_blank"><b>Julien Muke</b></a> YouTube. Feel free to subscribe 🔔!
    </div>
</div>

## 🚨 Tutorial

This repository contains the steps corresponding to an in-depth tutorial available on my YouTube
channel, <a href="http://www.youtube.com/@julienmuke/videos" target="_blank"><b>Julien Muke</b></a>.

If you prefer visual learning, this is the perfect resource for you. Follow my tutorial to learn how to build projects
like these step-by-step in a beginner-friendly manner!

<a href="https://youtu.be/o4fNDCAqyzM" target="_blank"><img src="https://github.com/sujatagunale/EasyRead/assets/151519281/1736fca5-a031-4854-8c09-bc110e3bc16d" /></a>

## <a name="introduction">🤖 Introduction</a>

In this hands-on project, we'll build a real-time AI-powered threat detection and response system on AWS using GuardDuty, SNS, and Lambda. This setup will enable you to automatically detect threats and take immediate action, significantly improving your security posture. Simulate abnormal behavior in an AWS environment and use AI-powered tools to detect, respond, and notify you in real time.

## <a name="steps">🛠 Tech Stack: </a>

This project showcases a real-time AI-powered security pipeline using:

- Amazon CloudTrail (log API activity)
- Amazon GuardDuty (AI-based threat detection)
- Amazon EventBridge (trigger on GuardDuty findings)
- AWS Lambda (automated response)
- Amazon SNS (send real-time email/SMS alerts)


Simulated GuardDuty findings, trigger SNS alerts and a Lambda function that sends a clean, human-readable security alert.

## 🔧 Prerequisites

✅ An AWS account<br>
✅ AWS CLI configured<br>
✅ IAM permissions to create: CloudTrail, GuardDuty, SNS, EventBridge, Lambda<br>


## ➡️ Step 1 - Enable CloudTrail

Amazon CloudTrail records all AWS API calls and activity in your account. GuardDuty analyzes these logs.

How to do it:

1. Go to the CloudTrail console
2. If it’s not already enabled: Click “Create trail”
3. Choose “Management events” → enable Read and Write events
4. Choose to log to an S3 bucket (create a new one if needed)
5. Leave Data events and Insights off (not needed here)
6. Click “Create trail”

✅ Now your account logs all actions taken by users, roles, and services.

## ➡️ Step 2 - Enable Amazon GuardDuty

Amazon GuardDuty will analyze CloudTrail, DNS, VPC Flow Logs, and more using ML + threat intel to detect suspicious behavior.

How to do it:

1. Go to the GuardDuty console
2. Click “Enable GuardDuty”
3. Wait 5-10 mins, it starts analyzing logs.

✅ GuardDuty is now scanning your account for threats like credential theft, unusual login behavior, port scanning, and more.

## ➡️ Step 3 - Set Up an SNS Topic for Notifications

Next, we'll create an SNS topic to send alerts to your security team.

How to do it:

1. Go to the Amazon SNS console.
2. In the left navigation pane, click Topics, then Create topic.
3. Choose the Standard type.
4. Give your topic a name `GuardDuty-Threat-Alerts`
5. Scroll down and click Create topic.
6. Once the topic is created, you need to create a subscription. Click Create subscription.
7. For Protocol, choose Email (or another preferred method).
8. For Endpoint, enter your email address
9. Click Create subscription.


## ➡️ Step 4 - Create a Lambda Function - Our Alert Processor

We'll create a Lambda function that takes the complicated JSON output from GuardDuty and turns it into a simple message.

🔹 Create the Lambda IAM Role:

Go to the IAM console and create a new role:
1. For the trusted entity, select AWS service, and for the use case, choose Lambda.
2. On the permissions screen, add the `AWSLambdaBasicExecutionRole` policy. This allows our function to write logs to CloudWatch, which is essential for debugging.
3. Name the role something like `GuardDuty-Lambda-Role` and create it.

🔹 Create the Lambda Function:

1. Go to the Lambda console and click Create function.
2. Select Author from scratch.
3. Function name: `GuardDuty-Automated-Response`
4. Runtime: Python `3.13`
5. Architecture: `x86_64`
6. Permissions: Choose Use an existing role and select the IAM role you just created.
7. Click Create function.

Now, let's paste in our Python code. This code will parse the GuardDuty finding, pull out the most important details, and format a clean message.

<details>
<summary><code>GuardDuty-Automated-Response.py</code></summary>

```python
import boto3
import json
import os
from datetime import datetime

sns = boto3.client('sns')

def lambda_handler(event, context):
    try:
        detail = event["detail"]
        instance_id = detail["resource"]["instanceDetails"]["instanceId"]
        public_ip = detail["resource"]["instanceDetails"]["networkInterfaces"][0]["publicIp"]
        finding_type = detail["type"]
        region = detail["region"]
        description = detail["description"]
        time = detail["service"]["eventFirstSeen"]
        profile = detail["resource"]["instanceDetails"]["iamInstanceProfile"]["arn"]
        remote_ip = detail["service"]["action"]["networkConnectionAction"]["remoteIpDetails"]["ipAddressV4"]
        remote_port = detail["service"]["action"]["networkConnectionAction"]["remotePortDetails"]["port"]
        
        readable_message = f"""
🚨 GuardDuty Alert: Trojan Activity Detected

🔍 Type: {finding_type}
💡 Description: {description}

🖥 Instance ID: {instance_id}
🔐 Instance Profile: {profile}
🌐 Public IP: {public_ip}
➡️ Remote IP: {remote_ip}:{remote_port}
📍 Region: {region}
🕒 Time: {datetime.strptime(time, "%Y-%m-%dT%H:%M:%S.%fZ").strftime('%Y-%m-%d %H:%M:%S')} UTC

🧠 Recommendation:
Isolate or stop the EC2 instance and investigate for malware or unauthorized traffic.

📘 Learn more: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings.html
"""

        sns.publish(
            TopicArn=os.environ["SNS_TOPIC_ARN"],
            Subject="🚨 GuardDuty: Trojan:EC2/BlackholeTraffic Detected",
            Message=readable_message
        )

        return {
            'statusCode': 200,
            'body': f"Formatted alert sent to SNS topic for instance {instance_id}"
        }

    except Exception as e:
        print("Error:", str(e))
        return {
            'statusCode': 500,
            'body': f"Error processing event: {str(e)}"
        }

```
</details>

🔹 Configure Environment Variables:

1. In your Lambda function's configuration, go to the Environment variables tab and click Edit.
2. Add a new variable:
<br>• Key: `SNS_TOPIC_ARN`
<br>• Value: Paste the ARN of the SNS topic you created in Step 2.

🔹 Attach a Policy to Allow SNS:Publish:

1. In your Lambda function in the AWS Console
2. Go to Configuration > Permissions
3. Click the role name `GuardDuty-Lambda-Role`  this will take you to the IAM Role details.
4. From the IAM Role page, "Add permissions" > "Attach policies"
5. Choose “Create inline policy” (for full control)
6. Create and Attach Inline Policy, use the following JSON in the JSON tab:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "sns:Publish",
      "Resource": "arn:aws:sns:your-region:your-account-id:your-topic-name"
    }
  ]
}
```

⚠️ Note: Replace `your-region` `your-account-id` `your-topic-name` with your actual values.

7. Click Next, give it a name like `AllowSNSPublish`
8. Click Create policy

Now this role can successfully publish to your SNS topic!

## ➡️ Step 5 - Integrate Services with Amazon EventBridge

Now, we'll create an EventBridge rule to trigger our Lambda function and send a notification when GuardDuty detects a specific type of threat.

1. Go to the Amazon EventBridge console.
2. In the left navigation pane, click Rules, then Create rule.
3. Give it a name like `GuardDuty-EC2-Threat-Rule`
4. Event bus: default
5. Rule type: Rule with an event pattern
6. Click Next.
7. Event source: AWS events or EventBridge partner events
8. Event pattern:
  <br>• Event source: AWS services
  <br>• AWS service: GuardDuty
  <br>• Event type: GuardDuty Finding

```json
{
  "source": ["aws.guardduty"],
  "detail-type": ["GuardDuty Finding"],
  "detail": {
    "type": ["Trojan:EC2/BlackholeTraffic"]
  }
}
```
9. Click Next.
10. Select a target:
<br>• Target 1:
      <br>• Target types: AWS service
      <br>• Select a target: Lambda function
      <br>• Function: Select the `GuardDuty-Automated-Response` function.

11. Click Next and then Create rule.

### 🏆 Let's Test It!

We will use the AWS CLI to generate a sample GuardDuty finding that simulates a threat from our test user. This is the most direct way to trigger the entire workflow.

1. Open your terminal or command prompt that has the AWS CLI configured.
2. Find your GuardDuty Detector ID:
  <br>• Navigate to the GuardDuty console.
  <br>• Click on Settings in the left sidebar.
  <br>• Copy the Detector ID.
3. Run the command: Replace `YOUR_DETECTOR_ID` with your actual Detector ID .

```bash
aws guardduty create-sample-findings \
--detector-id YOUR_DETECTOR_ID \
--finding-types "Trojan:EC2/BlackholeTraffic"
```

This command tells GuardDuty to create a sample finding that mimics anomalous behavior from an EC2 instance that is making outbound connections to known malware, which will trigger our EventBridge rule.

### Verification - Check the Results ✅

Now, let's verify that each component of our project worked as expected.

1. Check for the SNS Notification
<br>• Go to your email inbox that you subscribed to the SNS topic.
<br>• You should receive an email with a subject line like: 🚨 `Trojan:EC2/BlackholeTraffic`

2. Check the Lambda Function Logs
<br>• Navigate to the Lambda console and select your `GuardDuty-Automated-Response` function.
<br>• Click on the Monitor tab, and then View CloudWatch logs.


## 🗑️ Cleaning Up

When you are finished with the project, you can destroy all the created AWS resources to avoid incurring further costs.
