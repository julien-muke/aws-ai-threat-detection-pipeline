# ![aws](https://github.com/julien-muke/Search-Engine-Website-using-AWS/assets/110755734/01cd6124-8014-4baa-a5fe-bd227844d263) Real-Time Threat Detection on AWS with AI | GuardDuty, CloudTrail, Lambda & SNS 🛡️

<div align="center">

  <br />
    <a href="https://youtu.be/o4fNDCAqyzM" target="_blank">
      <img src="https://github.com/user-attachments/assets/d9a86018-563e-46a3-a7f3-6c6bb3514842" alt="Project Banner">
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

- ✅ Amazon CloudTrail (log API activity)
- ✅ Amazon GuardDuty (AI-based threat detection)
- ✅ Amazon EventBridge (trigger on GuardDuty findings)
- ✅ AWS Lambda (automated response)
- ✅ Amazon SNS (send real-time email/SMS alerts)


Simulated GuardDuty findings, trigger SNS alerts and a Lambda function that sends a clean, human-readable security alert.

## 🔧 Prerequisites

✅ An AWS account<br>
✅ AWS CLI configured<br>
✅ IAM permissions to create: CloudTrail, GuardDuty, SNS, EventBridge, Lambda<br>
✅ Optional: VPN or proxy to simulate foreign IP access<br>


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
3. Wait 5–10 mins — it starts analyzing logs.

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
8. For Endpoint, enter the email address of your security team.
9. Click Create subscription.


## ➡️ Step 4 - Create a Lambda Function - Our Alert Processor

We'll create a Lambda function that takes the complicated JSON output from GuardDuty and turns it into a simple message.

- Create the Lambda IAM Role:

Go to the IAM console and create a new role:
1. For the trusted entity, select AWS service, and for the use case, choose Lambda.
2. On the permissions screen, add the `AWSLambdaBasicExecutionRole` policy. This allows our function to write logs to CloudWatch, which is essential for debugging.
3. Name the role something like `GuardDuty-Lambda-Role` and create it.

- Create the Lambda Function:

1. Go to the Lambda console and click Create function.
2. Select Author from scratch.
3. Function name: `GuardDuty-Automated-Response`
4. Runtime: Python `3.9`
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

Here is some CSS to make the interface look professional and modern.

<details>
<summary><code>frontend/style.css</code></summary>

```css
@import url('https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;700&display=swap');

body {
    font-family: 'Roboto', sans-serif;
    background-color: #f0f2f5;
    color: #333;
    margin: 0;
    padding: 20px;
    display: flex;
    justify-content: center;
    align-items: center;
    min-height: 100vh;
}

.container {
    width: 100%;
    max-width: 800px;
    background-color: #ffffff;
    border-radius: 12px;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.1);
    padding: 30px;
    box-sizing: border-box;
}

header {
    text-align: center;
    border-bottom: 1px solid #e0e0e0;
    padding-bottom: 20px;
    margin-bottom: 30px;
}

header h1 {
    color: #1a73e8;
    margin: 0;
}

.upload-area {
    text-align: center;
    margin-bottom: 30px;
}

#imageUpload {
    display: none;
}

#uploadLabel {
    display: block;
    padding: 30px;
    border: 2px dashed #1a73e8;
    border-radius: 8px;
    cursor: pointer;
    background-color: #f8f9fa;
    margin-bottom: 20px;
    transition: background-color 0.3s;
}

#uploadLabel:hover {
    background-color: #e8f0fe;
}

#uploadLabel span {
    font-size: 1.2em;
    font-weight: 500;
}

#analyzeBtn {
    background-color: #1a73e8;
    color: white;
    padding: 12px 25px;
    border: none;
    border-radius: 8px;
    font-size: 1em;
    cursor: pointer;
    transition: background-color 0.3s, box-shadow 0.3s;
    box-shadow: 0 2px 5px rgba(0,0,0,0.1);
}

#analyzeBtn:disabled {
    background-color: #cccccc;
    cursor: not-allowed;
}

#analyzeBtn:not(:disabled):hover {
    background-color: #155ab6;
    box-shadow: 0 4px 10px rgba(0,0,0,0.2);
}

#preview {
    text-align: center;
    margin-bottom: 30px;
}

#imagePreview {
    max-width: 100%;
    max-height: 400px;
    border-radius: 8px;
    display: none;
    box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
}

#results {
    background-color: #f8f9fa;
    border-radius: 8px;
    padding: 20px;
}

#results.hidden {
    display: none;
}

#resultContent {
    display: none;
}

#description {
    font-size: 1.1em;
    line-height: 1.6;
    margin-bottom: 20px;
    font-style: italic;
    color: #555;
}

#labels {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
}

.label-tag {
    background-color: #e8f0fe;
    color: #1a73e8;
    padding: 8px 15px;
    border-radius: 20px;
    font-size: 0.9em;
    font-weight: 500;
}

.loader {
    border: 4px solid #f3f3f3;
    border-top: 4px solid #1a73e8;
    border-radius: 50%;
    width: 40px;
    height: 40px;
    animation: spin 1s linear infinite;
    margin: 20px auto;
}

@keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
}

footer {
    text-align: center;
    margin-top: 30px;
    padding-top: 20px;
    border-top: 1px solid #e0e0e0;
    font-size: 0.9em;
    color: #888;
}
```
</details>

This JavaScript file handles the logic for image preview, converting the image to base64, calling the API, and displaying the results.

<details>
<summary><code>frontend/script.js</code></summary>

```js
document.addEventListener('DOMContentLoaded', () => {
    const imageUpload = document.getElementById('imageUpload');
    const uploadLabel = document.getElementById('uploadLabel');
    const analyzeBtn = document.getElementById('analyzeBtn');
    const imagePreview = document.getElementById('imagePreview');
    const previewContainer = document.getElementById('preview');
    const resultsContainer = document.getElementById('results');
    const loader = document.getElementById('loader');
    const resultContent = document.getElementById('resultContent');
    const descriptionEl = document.getElementById('description');
    const labelsEl = document.getElementById('labels');

    const API_ENDPOINT = 'YOUR_API_GATEWAY_INVOKE_URL'; // <-- IMPORTANT: REPLACE THIS

    let base64Image = null;

    imageUpload.addEventListener('change', (event) => {
        const file = event.target.files[0];
        if (file) {
            // Display image preview
            const reader = new FileReader();
            reader.onload = (e) => {
                imagePreview.src = e.target.result;
                imagePreview.style.display = 'block';
                uploadLabel.querySelector('span').textContent = file.name;
                analyzeBtn.disabled = false;
            };
            reader.readAsDataURL(file);

            // Convert image to base64 for sending to API
            const readerForBase64 = new FileReader();
            readerForBase64.onload = (e) => {
                // Remove the data URL prefix (e.g., "data:image/jpeg;base64,")
                base64Image = e.target.result.split(',')[1];
            };
            readerForBase64.readAsDataURL(file);
        }
    });

    analyzeBtn.addEventListener('click', async () => {
        if (!base64Image || API_ENDPOINT === 'YOUR_API_GATEWAY_INVOKE_URL') {
            alert('Please select an image first or configure the API endpoint in script.js.');
            return;
        }

        // Show loader and results section
        resultsContainer.classList.remove('hidden');
        loader.style.display = 'block';
        resultContent.style.display = 'none';
        descriptionEl.textContent = '';
        labelsEl.innerHTML = '';

        try {
            const response = await fetch(API_ENDPOINT, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ image: base64Image }),
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || `HTTP error! status: ${response.status}`);
            }

            const data = await response.json();

            // Display results
            descriptionEl.textContent = data.description;
            data.labels.forEach(label => {
                const labelTag = document.createElement('div');
                labelTag.className = 'label-tag';
                labelTag.textContent = label;
                labelsEl.appendChild(labelTag);
            });

        } catch (error) {
            console.error('Error:', error);
            descriptionEl.textContent = `An error occurred: ${error.message}`;
        } finally {
            // Hide loader and show content
            loader.style.display = 'none';
            resultContent.style.display = 'block';
        }
    });
});
```
</details>


## ➡️ Step 5 - Deployment and Testing

Now it's time to bring everything online.

### 1. Deploy the Backend with Terraform

• Navigate to the `terraform` directory in your terminal:

```bash
cd ai-image-recognition-terraform/terraform
```

• Initialize Terraform. This will download the necessary provider plugins.

```bash
terraform init
```

• Plan the deployment. This shows you what resources Terraform will create.

```bash
terraform plan
```

• Apply the configuration to create the AWS resources. Type `yes` when prompted.

```bash
terraform apply
```

• After the deployment is complete, Terraform will display the outputs. Copy the `api_gateway_invoke_url`

### 2. Configure and Deploy the Frontend

• Open `frontend/script.js` in your text editor.<br>
⚠️Important: You will need to replace `YOUR_API_GATEWAY_INVOKE_URL` with the actual URL you get from the Terraform output. Make sure to add `/analyze` to the end of the URL you copied.<br>
• Now, upload the frontend files (`index.html`, `style.css`, and the updated `script.js`) to the S3 bucket created by Terraform. You can do this via the AWS Management Console or using the AWS CLI.<br>

➖ Find your bucket name in the S3 console (it will be prefixed with `ai-image-analyzer-frontend-hosting`).<br>
➖ Upload the three files from your `frontend` directory into the bucket.<br>
➖ Ensure the files have public read access. Terraform attempts to set this, but you may need to confirm.<br>

### 3. Test the Application

1. Go to your S3 bucket, choose on index.html then open Object URL in your web browser.
2. You should see the "AI Image Analyzer" interface.
3. Click the upload area, select a JPG or PNG image from your computer.
4. The image preview will appear, and the "Analyze Image" button will be enabled.
5. Click the button. The loader will appear while the backend processes the image.
6. After a few moments, the AI-generated description and the list of detected labels will be displayed.

![Image](https://github.com/user-attachments/assets/f5130fef-d343-40a7-998b-bc065078eb2c)

## 🗑️ Cleaning Up

When you are finished with the project, you can destroy all the created AWS resources to avoid incurring further costs.

1. Navigate back to the terraform directory.
2. Run the destroy command:

```bash
terraform destroy
```