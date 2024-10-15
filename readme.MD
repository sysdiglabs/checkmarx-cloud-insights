# sysdig-checkmarx-cloud-insights


# Questions
- Persist account ids. Explore /aacounts/enrich to retrieve the list of accounts
  
# Tech debt (validate first)
- Store cloud-account-id to enable automatic refresh (it is manual for now)
- Evaluate extending it to other workload types like statefulsets, daemonsets, cronjobs, jobs 
- Refine python for AWS Lambda

## Execute locally
python-lambda-local -t 15 -f lambda_handler lambda_function.py event.json


### Pack the function (optional)

mkdir generated-lambda
cp lambda_function.py generated-lambda/lambda_function.py
cp event.json generated-lambda/event.json
cd generated-lambda
mkdir python
pip install requests -t ./python
zip -r9 lambda_function.zip .


### Deploy to AWS

1. Go to the AWS Console and browse to Lambda Functions
2. New Lambda. Choose Python Runtime 3.12
3. Once created set the timeout (60 seconds recommended depending on the amount of data)
4. Create the environment vars in Configuration
