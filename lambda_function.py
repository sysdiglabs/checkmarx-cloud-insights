import json
import os
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
TIMEOUT_TIME = 15

# Load system vars
sysdig_url = os.environ['sysdig_url']
sysdig_token = os.environ['sysdig_token']
checkmarx_url = os.environ['checkmarx_url']
checkmarx_token = os.environ['checkmarx_token']
checkmarx_extid = os.environ['checkmarx_extid']
checkmarx_tenant = os.environ['checkmarx_tenant']

# Sysdig API specific values
sysdig_endpoint_inventory = "/secure/inventory/v1/resources"
sysdig_param_object_image = "image"
sysdig_param_object_deployment = "deployment"
sysdig_param_object_cluster = "cluster"
sysdig_param_object_matched = "matched"
# Checkmarx
cx_integration_name = "SysdigTest"

http = urllib3.PoolManager()

def lambda_handler(event, context):
    # Request clusters (not required for now, they are extracted from the list of workloads)
    #sysClusters = sysGetAllObjects(sysdig_param_object_cluster, sysdig_url, sysdig_endpoint_inventory, sysdig_token)
    # Request images (not required for now, all the info is extracted from the list of workloads)
    #sysImages = sysGetAllObjects(sysdig_param_object_image, sysdig_url, sysdig_endpoint_inventory, sysdig_token)

    statusCode = 500   

    # Var initialization
    required_env_vars = ['sysdig_url', 'sysdig_token', 'checkmarx_url', 'checkmarx_token', 'checkmarx_extid', 'checkmarx_tenant']
    for var in required_env_vars:
        if not os.getenv(var):
            raise ValueError(f"Environment variable {var} is missing")

    # Request deployments
    sysDeployments = sysGetAllObjects(sysdig_param_object_deployment, sysdig_url, sysdig_endpoint_inventory, sysdig_token)
    # saveJsonFile(sysDeployments, sysdig_param_object_deployment) # Debug

    clusters_dict = {}

    if sysDeployments:
        # Iterate over the list of results building the data that will be sent to Checkmarx
        for deployment in sysDeployments:
            if 'cluster' in deployment["metadata"]:
                cluster_name = deployment["metadata"]["cluster"]
                if cluster_name not in clusters_dict:
                    clusters_dict[cluster_name] = sysClusterTemplate(cluster_name)

                for container in deployment["containerInfo"]:
                    if container["containerName"] and container["podName"]:
                        clusters_dict[cluster_name]["pods"].append(
                            sysPodTemplate(
                                container["podName"],
                                container["containerName"],
                                container["pullString"],
                                deployment["isExposed"]
                            )
                        )

        clusters = {
            "externalID": f"{checkmarx_extid}",
            "clusters": list(clusters_dict.values())
        }

        # Checkmarx authentication and data upload
        success = False
        cxRefreshToken = cxAuthenticate(checkmarx_url, checkmarx_tenant, checkmarx_token)
        # If Auth is ok, proceed to feed sysdig discovered data
        if cxRefreshToken:
            success, enrichmentAccountID = cxUploadSysdigData(checkmarx_url, checkmarx_tenant, cxRefreshToken, checkmarx_extid, clusters)
            if success:
                statusCode = 200 
    
    return {
        "statusCode": statusCode,
        "body": json.dumps({
            "clusters": clusters,
            "Checkmarx Response": success
        })
    }

# Template for pod information
def sysPodTemplate(pod_name, container_name, pull_string, is_exposed):
    return {
        "name": pod_name,
        "ips": [],
        "containers": [
            {
                "name": container_name,
                "image": pull_string,
                "publicExposed": is_exposed
            }
        ]
    }

# Template for cluster information
def sysClusterTemplate(cluster_name):
    return {
        "name": cluster_name,
        "region": "",
        "pods": []
    }

def sysGetAllObjects(objectType, url_sysdig, endpoint_inventory_sysdig, sysdig_bearer_token):
    base_url = "https://" + url_sysdig + endpoint_inventory_sysdig
    filter_query = "type = \"" + objectType + "\""
    enriched_containers = True
    page_size = 500  
    page_number = 1
    all_data = []

    headers = {
        'Authorization': 'Bearer ' + sysdig_bearer_token,  
        'Content-Type': 'application/json'
    }

    while True:
        params = {
            'filter': filter_query,
            'withEnrichedContainers': enriched_containers,
            'pageSize': page_size,
            'pageNumber': page_number
        }

        encoded_params = urllib3.request.urlencode(params)
        response = http.request('GET', base_url + '?' + encoded_params, headers=headers, timeout=TIMEOUT_TIME)
        
        if not evalResp(response.status, response.data, "a01"):
            return None
        
        response_data = json.loads(response.data.decode('utf-8'))
        all_data.extend(response_data['data'])

        page_info = response_data['page']
        if page_number >= page_info['total']:
            break
        page_number = page_info['next']
    
    return all_data

def evalResp(code, data, opId):
    if code not in [200, 201]:
        print("HTTP request error (" + opId + "):", code, data)
        return False
    
    return True

def cxAuthenticate(url_checkmarx, tenant_checkmarx, token_checkmarx):
    base_url = f"https://{url_checkmarx}/auth/realms/{tenant_checkmarx}/protocol/openid-connect/token"
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    payload = {'refresh_token': token_checkmarx, 'grant_type': 'refresh_token', 'client_id': 'ast-app'}

    encoded_payload = urllib3.request.urlencode(payload)
    response = http.request('POST', base_url, body=encoded_payload, headers=headers, timeout=TIMEOUT_TIME)
    result = None
    if evalResp(response.status, response.data, "cx1a"):
        result = json.loads(response.data.decode('utf-8')).get('access_token')

    return result

def cxUploadSysdigData(url_checkmarx, tenant_checkmarx, refresh_token_checkmarx, sysdig_extID_checkmarx, clustersJSON):
    accountID = cxEnrichmentAccount(url_checkmarx, tenant_checkmarx, refresh_token_checkmarx, sysdig_extID_checkmarx)
    uploadURL = cxGetUploadUrl(url_checkmarx, tenant_checkmarx, refresh_token_checkmarx)
    jsonUploaded = cxUploadJSON(refresh_token_checkmarx, uploadURL, clustersJSON)
    enrichmentTriggered = cxTriggerEnrichment(url_checkmarx, refresh_token_checkmarx, accountID, uploadURL)
    return enrichmentTriggered, accountID

def cxCheckOrCreateAccount(accounts, integrationName):
    if not accounts:
        return False
    
    for account in accounts:  
        if account.get('name') == integrationName:
            return account.get('id')
    
    return False


def cxEnrichmentAccount(url_checkmarx, tenant_checkmarx, refresh_token_checkmarx, sysdig_extID_checkmarx):
    base_url = f"https://{url_checkmarx}/api/cnas/accounts"
    headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + refresh_token_checkmarx}
    response = http.request('GET', base_url, headers=headers, timeout=TIMEOUT_TIME)
    result = None
    if not evalResp(response.status, response.data, "cx2a"):
        return None
    accounts = json.loads(response.data.decode('utf-8')).get('data')
    # Use an existing account from Checkmarx Cloud Insights
    accountFound = cxCheckOrCreateAccount(accounts, cx_integration_name)
    if accountFound:
        result = accountFound
    else:
        # Create a new account if no sysdig accounts exists in Checkmarx Cloud Insights
        base_url = f"https://{url_checkmarx}/api/cnas/accounts/enrich"
        headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + refresh_token_checkmarx}
        payload = json.dumps({"name": cx_integration_name, "externalID": sysdig_extID_checkmarx})
        response = http.request('POST', base_url, body=payload, headers=headers, timeout=TIMEOUT_TIME)
        result = None
        if evalResp(response.status, response.data, "cx2b"):
            result = json.loads(response.data.decode('utf-8')).get('accountID')

    return result

def cxGetUploadUrl(url_checkmarx, tenant_checkmarx, refresh_token_checkmarx):
    base_url = f"https://{url_checkmarx}/api/uploads"
    headers = {'Authorization': 'Bearer ' + refresh_token_checkmarx}
    
    response = http.request('POST', base_url, headers=headers, timeout=TIMEOUT_TIME)
    result = None
    if evalResp(response.status, response.data, "cx3a"):
        result = json.loads(response.data.decode('utf-8')).get('url')

    return result

def cxUploadJSON(refresh_token_checkmarx, uploadURL, clustersjson):
    headers = {'Authorization': 'Bearer ' + refresh_token_checkmarx}
    payload = json.dumps(clustersjson)
    
    response = http.request('PUT', uploadURL, body=payload, headers=headers, timeout=TIMEOUT_TIME)
    result = None
    if evalResp(response.status, response.data, "cx4a"):
        result = True

    return result

def cxTriggerEnrichment(url_checkmarx, refresh_token_checkmarx, accountID, uploadURL):
    base_url = f"https://{url_checkmarx}/api/cnas/accounts/{accountID}/enrich"
    headers = {'Authorization': 'Bearer ' + refresh_token_checkmarx}
    payload = json.dumps({"uploadURL": uploadURL})
    
    response = http.request('POST', base_url, body=payload, headers=headers, timeout=TIMEOUT_TIME)
    result = None
    if evalResp(response.status, response.data, "cx5a"):
        result = json.loads(response.data.decode('utf-8')).get('message')

    return result    

def saveJsonFile(object, filename):
    with open(filename + ".json", 'w') as file:
        json.dump(object, file)
