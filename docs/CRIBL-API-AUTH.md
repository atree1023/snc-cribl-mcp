# Cribl API Authentication Guide

- For the complete documentation index, see [llms.txt](/llms.txt).

All Cribl API requests require you to authenticate with a Bearer token, except `GET /health` in the [global context](api#base-url-global) and `POST /auth/login`. In Cribl, Bearer tokens are [JSON Web Tokens (JWTs)](https://datatracker.ietf.org/doc/html/rfc7519).

You must include a valid Bearer token in the `Authorization` header of your API requests. The Bearer token verifies your identity and ensures secure access to the requested resources. The process for retrieving the Bearer token depends on whether you authenticate on [Cribl.Cloud and hybrid](#api-auth-cloud) deployments or in [on-prem](#api-auth-on-prem) deployments.

- In Cribl.Cloud and hybrid deployments, Bearer tokens are valid for `24` hours.

- In on-prem deployments, Bearer tokens expire according to the value you provide for the **Auth token TTL** setting at **Settings** > **Global** > **General Settings** > **API Server Settings** > **Advanced**. The default setting is `3600` seconds (`1` hour).

You are responsible for ensuring that your applications obtain a new Bearer token within the expiration window for each token.

- For on-prem deployments, if you're using SSO/OpenID Connect Authentication, you must toggle on **Allow login as Local User** in Cribl (see [Set Up Fallback Access](/iam/sso-on-prem/#fallback-access-on-prem)). You'll need to be a Local user when you authenticate.

- To use `https` for on-prem requests, you must [configure Transport Layer Security (TLS)](/stream/securing-tls/). If you do not configure TLS, use `http` instead. Use `http` only for testing in development environments. In production, configure TLS and use `https` to secure your communications.

## Authenticate in Cribl.Cloud and Hybrid Deployments {#api-auth-cloud}

To authenticate for API requests to [control plane](/cribl-as-code/control-plane/) (Cribl.Cloud or hybrid) or [management plane](/cribl-as-code/api-reference/management-plane/) (Cribl.Cloud) endpoints, first create an API Credential. The API Credential provides a **Client ID** and **Client Secret**. Provide these in a request to `https://login.cribl.cloud/oauth/token` to obtain a 24-hour Bearer token to authenticate subsequent API requests.

The authentication process is the same for [control plane](/cribl-as-code/control-plane/) and [management plane](/cribl-as-code/api-reference/management-plane/) requests. The only difference is the [base URL](api#base-urls) and endpoint you use for your API requests.

- On Cribl.Cloud Government, authentication requests use a different URL and request format. Log in to Cribl.Cloud Government to get a customized example of the authentication request.
- To open a Help drawer that displays the example, navigate to **Products > Cribl > Organization > API Credentials** and select the tooltip icon next to **Add Credential**.

- The **IP Allowlist** option for API Credentials is not supported on Cribl.Cloud Government.

You can create API Credentials with the `POST /api-credentials` endpoint in the Cribl [management plane API](/cribl-as-code/api-reference/management-plane/). However, you must first create the initial API Credential manually in the Cribl UI. This is necessary because Cribl API requests require a Bearer token, which in turn requires an API Credential. After you create the first API Credential, you can retrieve a Bearer token to use in [API requests to create new API Credentials](api-create-api-credentials).

To create an API Credential in the Cribl UI:

1. Log in to Cribl.Cloud as an Owner or an Admin.
2. On the top bar, select **Products**, and then select **Cribl**.
3. In the sidebar, select **Organization**, and then select **API Credentials**.
4. Select **Add Credential**.
5. Enter a **Name** and an optional **Description**.
6. Toggle to disable the Credential if needed.
7. In the **Organization Permissions** drop-down menu, select a [Permission](/iam/permissions#organization) to apply for the API Credential. **Organization Permissions** are available on [certain plan/license tiers](https://cribl.io/pricing/). Without a proper license, all API Credentials are granted the **Admin** Permission.
   - Choosing the **Admin** or **Owner** Permission automatically grants admin access to all Workspaces.

   - If you choose the **User** Permission, under **Workspace Access**, define the desired [Permissions](/iam/permissions#workspace) for specific [Workspaces](/stream/workspaces) and Cribl products.

   - To use the API Credential to grant read-only access on [individual Cribl Search resources](/search/sharing#share-datasets-dashboards) (for example, for a service account that connects to Cribl Search via API), select either the **User** or **Editor** Permission on Cribl Search. The **Admin** Permission automatically grants full access to all Cribl Search resources.

8. (Optional) Under **IP Allowlist**, you can restrict API access for the Credential to specific IPv4 Classless Inter-Domain Routing (CIDR) ranges. Select **Add CIDR** and enter the desired range. You can add a maximum of 10 CIDR ranges.
9. Select **Save**.

The **API Credentials** page displays the new API Credential within a few seconds.

The API Credential includes a **Client ID** and a **Client Secret** that Organization Owners and Admins can use to generate Bearer tokens. Organization Owners and Admins can view, edit, and disable existing API Credentials. Only Owners can delete API Credentials.

The **Client ID** and **Client Secret** are sensitive information and should be kept private.

## auth-request-example-api

Once you have the **Client ID** and **Client Secret**, provide them in the body of a request to `https://login.cribl.cloud/oauth/token` as shown in the following example request. The **Client ID** and **Client Secret** are sensitive information and should be kept private, so the example request shows how to provide them as variables.

## Authentication Request Example (Cribl.Cloud and Hybrid)

```shell
curl --request POST \
--url "https://login.cribl.cloud/oauth/token" \
--header "Content-Type: application/json" \
--data "{
  \"grant_type\": \"client_credentials\",
  \"client_id\": \"${clientId}\",
  \"client_secret\": \"${clientSecret}\",
  \"audience\": \"https://api.cribl.cloud\"
}"
```

As shown in the following example response, the JSON object in the response includes several attributes:

- `access_token`: The Bearer token to use in the `Authorization` header for authentication in subsequent API requests.
- `scope`: The [Permissions](/iam/permissions) that the Bearer token grants.
- `expires_in`: The number of seconds until the Bearer token expires. In Cribl.Cloud/hybrid, Bearer tokens expire `24` hours (`86400` seconds) after they are created. You are responsible for ensuring that your applications obtain a new Bearer token within the expiration window for each token.
- `token_type`: The type of the token. in Cribl.Cloud/hybrid, the value is always `Bearer`.

## Authentication Response Example (Cribl.Cloud/Hybrid)

{
  "access_token": "abcdefg1234567890...exampleBearerToken",
  "scope": "user:read:workergroups user:update:workergroups user:read:connections user:update:connections user:update:workspaces user:read:workspaces",
  "expires_in": 86400,
  "token_type": "Bearer"
}


To use the Bearer token in subsequent API requests, include it in the `Authorization` header as shown in this control plane example:

## API Request Example (Cribl.Cloud and Hybrid)

```shell
curl --request GET \
--url "https://${workspaceName}-${organizationId}.cribl.cloud/api/v1/system/inputs" \
--header "Authorization: Bearer abcdefg1234567890...exampleBearerToken" \
--header "Content-Type: application/json"
```

## Authenticate in On-Prem Deployments

To authenticate using the API in on-prem deployments, send a request to the `/auth/login` endpoint. The response includes the Bearer token required for subsequent API requests.

The following example request demonstrates an `/auth/login` request. Replace the variables in the example request with your hostname, port, and login credentials (username and password). Your username and password are sensitive information and should be kept private, so the example request shows how to provide them as variables.

## Authentication Request Example (On-Prem Deployment)

```shell
curl --request POST \
--url "https://${hostname}:${port}/api/v1/auth/login" \
--header "Content-Type: application/json" \
--data "{
  \"username\": \"${username}\",
  \"password\": \"${password}\"
}"
```

The response is a JSON object like the following example. The value of the `token` attribute in the response is the Bearer token:

## Authentication Response Example (On-Prem Deployment)

```json
{
  "token": "abcdefg1234567890...exampleBearerToken",
  "forcePasswordChange": false
}


To use the Bearer token in subsequent API requests, include it in the `Authorization` header, like this:

## API Request Example (On-Prem Deployment)

```shell
curl --request GET \
--url "https://${hostname}:${port}/api/v1/system/inputs" \
--header "Authorization: Bearer abcdefg1234567890...exampleBearerToken" \
--header "Content-Type: application/json"
```

## Authenticate and Create HEC Tokens with Python

Cribl Solutions Engineering developed an example script that demonstrates how to use Python to authenticate to the Cribl API, make a simple POST request, and add a new HEC token. The script and instructions for usage are available in the [`py_hec_token_mgr` GitHub repo](https://github.com/camrunr/py_hec_token_mgr).

To use the script, you'll need:

- Python 3.
- The Python 3 Requests module (use brew or pip3 to install).
- A working, distributed Cribl Stream or Edge installation, with a configured [Splunk HEC Source](/stream/sources-splunk-hec).
- An admin username and password.
````
