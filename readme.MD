# sysdig-checkmarx-cloud-insights

## Deploy to AWS

1. Go to the AWS Console > Lambda Functions
2. New Lambda. Set the name and choose Python Runtime 3.12
3. Once created, go to Configuration > General configuration and set the timeout (60 seconds recommended depending on the amount of data)
4. Configuration > Environment variables (Create and set environment vars)

    sysdig_token="<SYSDIG_TOKEN>"
    sysdig_url="<SYSDIG_URL>"
    checkmarx_url="<CHECKMARX_URL>"
    checkmarx_tenant="<CHECKMARX_TENANT>"
    checkmarx_token="<CHECKMARX_TOKEN>"
    checkmarx_extid="<CHECKMARX_EXTID>"

5. Deploy and test
6. Schedule it (Function overview > Add Trigger > Schedule "rate(1day)" for daily synchronization).


## Tech debt (validate first)
- Evaluate extending the integration to other workload types like statefulsets, daemonsets, cronjobs, jobs 

## Test it locally
Install [python-lambda-local](https://pypi.org/project/python-lambda-local/)
python-lambda-local -t 15 -f lambda_handler lambda_function.py event.json


## Pack the function (optional)
mkdir generated-lambda
cp lambda_function.py generated-lambda/lambda_function.py
cp event.json generated-lambda/event.json
cd generated-lambda
mkdir python
pip install requests -t ./python
zip -r9 lambda_function.zip .
