# sysdig-checkmarx-cloud-insights

## Information

This script enriches Checkmarx Cloud Insights with Sysdig detections. 

Please note that it is limited to Kubernetes deployments for now. 

## Instructions

### 1. Deploy to AWS

1. Download the file `lambda_function.py` containing the Lambda code for the integration.
2. Navigate to the [AWS Lambda Console](https://console.aws.amazon.com/lambda).
3. Click on **Create function**.
4. Fill in the function details:
   - **Function name**: (Give your function a name)
   - **Runtime**: Select **Python 3.12** from the dropdown.
5. Click **Create function** > **Code** section.
7. Paste the code directly into the editor (Aternatively you can zip the `lambda_function.py` file and upload as zip).
8. Once uploaded or pasted, click **Deploy**.


### 2. Set Environment Variables

1. From your Lambda function’s details page, click on the **Configuration** tab.
2. Select **Environment variables** > **Edit**.
3. Add the required key-value pairs (environment variables). 
```python
    sysdig_token="<SYSDIG_TOKEN>"
    sysdig_url="<SYSDIG_URL>"
    checkmarx_url="<CHECKMARX_URL>"
    checkmarx_tenant="<CHECKMARX_TENANT>"
    checkmarx_token="<CHECKMARX_TOKEN>"
    checkmarx_extid="<CHECKMARX_EXTID>"
```
4. Once done, click **Save**.

### 3. Schedule the Lambda Function

1. In the Lambda console, go to your function’s **Configuration** tab.
2. Select **Triggers** on the left menu > **Add trigger**.
3. In the **Select a source** dropdown, choose **EventBridge (CloudWatch Events)**.
4. Select **Create a new rule** > **Rule type**: **Scheduled expression**.
5. Use the following **cron expression** to schedule the function daily at midnight:
   ```cron
   cron(0 0 * * ? *)
   ```
   (If you prefer, you can also use a rate expression such as `rate(1 day)`
6. Click **Add** to save the trigger.

### 4. Check Lambda execution

1. Trigger it manually if you want to validate the integration and review CloudWatch logs.
2. You can set CloudWatch alarms to monitor that your Lambda function schedule is working properly.

## Test it with python-lambda-locally

1. Set env vars (read above).

2. python-lambda-local -t 15 -f lambda_handler lambda_function.py <desired-params>
