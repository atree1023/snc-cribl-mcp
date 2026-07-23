> For the complete documentation index, see [llms.txt](https://docs.cribl.io/llms.txt).

The Cribl API is a RESTful API that provides a centrally managed control plane for programmatically configuring and managing Cribl resources. Developers can use the API to:

- Retrieve and manage data.
- Automate repetitive manual processes.
- Integrate with third-party applications.
- Consistently replicate environments and resources for testing, development, and deployment.

The Cribl API generally follows a resource-based structure in which each endpoint corresponds with a specific Cribl resource or collection of resources. In request URLs, resource-specific paths branch off from the [base URL](#base-urls).

Read the [Authentication](api-auth) page to learn how to authenticate to the Cribl API.

> ##### About PATCH Requests {{< id `about-patch` >}}
>
> In the Cribl API for the control plane, PATCH requests require a complete representation of the resource that you want to update. Endpoints that use the PATCH method do not support partial updates. Cribl removes any omitted fields when updating the resource. If you use a GET request to retrieve an existing configuration to use in the body of a PATCH request, confirm that the configuration is correct. If the existing configuration is incorrect, the updated resource may not function as expected. The [Update Configurations](update-configurations) example demonstrates how to update a Destination using the PATCH method.
>
> The Cribl API for the management plane does support partial updates for endpoints that use the PATCH method.
> {.box .warning}

## Try It Out {#try-it-out}

The [API Reference](https://docs.cribl.io/api-reference/) is also available in Cribl at **Settings** > **Global** > **API Reference**. We recommend using the in-product API Reference because it features a **Try it out** button for each endpoint that you can use to construct and execute a `curl` command and examine the response. The in-product API Reference aligns with your environment and provides a seamless testing experience.

At the top of the in-product API Reference, a **Servers** drop-down menu lists the base URLs associated with your Stream Leader and Worker Groups, Edge Fleets, and Search instance. **Try it out** commands use the base URL that you select from the **Servers** drop-down menu. The default selection in the **Servers** drop-down is the base URL for your Leader.

## Base URLs {#base-urls}

The base URL is the root address for making requests to the Cribl API. The standardized base URL format provides a consistent, predictable pattern.

Follow the format examples in this section to construct the base URL for your Cribl deployment. The correct base URL depends first on whether the target endpoint is in the [control plane](#control-plane-base-url) or [management plane](#mgmt-plane-base-url). For control plane endpoints, the base URL further depends on whether the target endpoint operates in the [global](#base-url-global), [Group/Fleet or Host](#base-url-group-fleet-host), or [Cribl Search](#base-url-cribl-search) context.

In [hybrid deployments](https://docs.cribl.io/stream/cloud-enterprise/#hybrid) with a Cribl.Cloud Leader and on-prem workers, API requests use the Cribl.Cloud base URL format. This is true even in the [Group/Fleet or Host](#base-url-group-fleet-host) context because API requests are served from the Cribl.Cloud Leader.

> On Cribl.Cloud Government, API requests use a different base URL. Log in to Cribl.Cloud Government to get a customized base URL example.
> To open a Help drawer that displays the example, navigate to **Products > Cribl > Organization > API Credentials** and select the tooltip icon next to **Add Credential**.

{.box .cloud}

To compose the complete URL for a request to a specific endpoint, append the endpoint path that is listed in the [API Reference](https://docs.cribl.io/api-reference/) to the base URL.

### Control Plane Base URLs {#control-plane-base-url}

The control plane provides operational control over Cribl resources. The control plane is supported for Cribl.Cloud/hybrid and on-prem deployments, and the base URL varies for target endpoints in the [global](#base-url-global), [Group/Fleet or Host](#base-url-group-fleet-host), or [Cribl Search](#base-url-cribl-search) context.

#### Global Context {#base-url-global}

For API requests to endpoints that apply to the entire Workspace or Organization (Cribl.Cloud/hybrid) or instance (on-prem), use the base URL for global requests. Examples of requests with a global scope include managing feature settings and resources outside of the context of a specific Worker Group or Fleet.

In Cribl.Cloud and hybrid deployments, the base URL format for global requests for Cribl Stream, Edge, and Lake endpoints is:

```
https://${workspaceName}-${organizationId}.cribl.cloud/api/v1
```

For single-instance on-prem deployments, use the following base URL format for global requests:

```
https://${hostname}:${port}/api/v1
```

For example, to send a request to the `GET /system/settings/git-settings` endpoint to retrieve the git settings for the Organization or instance, the complete URL is:

{{% tabs "cloud" "cloud" "Cribl.Cloud and Hybrid Example (Global)" "on-prem" "On-Prem Example (Global)" %}}
{{% tab-item "cloud" %}}

```
https://${workspaceName}-${organizationId}.cribl.cloud/api/v1/system/settings/git-settings
```

{{% /tab-item %}}
{{% tab-item "on-prem" %}}

```
https://${hostname}:${port}/api/v1/system/settings/git-settings
```

{{% /tab-item %}}
{{% /tabs %}}

#### Group/Fleet or Host Context {#base-url-group-fleet-host}

Some endpoints operate in the context of a specific Worker Group or Edge Fleet or host (Worker or Edge Node). In these cases, the base URL format includes additional URL segments that identify the context and the particular Group/Fleet or Node.

| Context                                            | URL Segments      | Example                                                                      |
| -------------------------------------------------- | ----------------- | ---------------------------------------------------------------------------- |
| Endpoints that target a specific Group/Fleet       | `/m/${groupName}` | List the commit history for a Worker Group or Edge Fleet with `GET /version` |
| Endpoints that act on a single Worker or Edge Node | `/w/${nodeId}`    | Get host metadata with `GET /edge/metadata`                                  |

##### Base URL for the Group or Fleet Context {#base-url-group-fleet}

For requests that are specific to a Worker Group or Edge Fleet, the base URL includes the `/m` context indicator and the name of the target Worker Group or Fleet:

{{% tabs "cloud" "cloud" "Cribl.Cloud and Hybrid (Worker Group/Edge Fleet)" "on-prem" "On-Prem (Worker Group/Edge Fleet)" %}}
{{% tab-item "cloud" %}}

```
https://${workspaceName}-${organizationId}.cribl.cloud/api/v1/m/${groupName}
```

{{% /tab-item %}}
{{% tab-item "on-prem" %}}

```
https://${hostname}:${port}/api/v1/m/${groupName}
```

{{% /tab-item %}}
{{% /tabs %}}

> If your license is limited to a single Worker Group, the `groupName` is always `default`.
> {.box .info}

For example, to send a request to the `POST /system/outputs` endpoint to create a Destination for the Worker Group `myDevGroup`, the complete URL is:

{{% tabs "cloud" "cloud" "Cribl.Cloud and Hybrid Example (Worker Group/Edge Fleet)" "on-prem" "On-Prem Example (Worker Group/Edge Fleet)" %}}
{{% tab-item "cloud" %}}

```
https://${workspaceName}-${organizationId}.cribl.cloud/api/v1/m/myDevGroup/system/outputs
```

{{% /tab-item %}}
{{% tab-item "on-prem" %}}

```
https://${hostname}:${port}/api/v1/m/myDevGroup/system/outputs
```

{{% /tab-item %}}
{{% /tabs %}}

##### Base URL for the Host Context {#base-url-host}

For requests that are specific to a certain host (Worker or Edge Node), the base URL includes the `/w` context indicator and the ID of the target Worker or Edge Node:

{{% tabs "cloud" "cloud" "Cribl.Cloud and Hybrid (Worker/Edge Nodes)" "on-prem" "On-Prem (Worker/Edge Nodes)" %}}
{{% tab-item "cloud" %}}

```
https://${workspaceName}-${organizationId}.cribl.cloud/api/v1/w/${nodeId}
```

{{% /tab-item %}}
{{% tab-item "on-prem" %}}

```
https://${hostname}:${port}/api/v1/w/${nodeId}
```

{{% /tab-item %}}
{{% /tabs %}}

To get the `nodeId`, send a request to the `GET /products/{product}/workers` endpoint using the [global context](#base-url-global) for the base URL. The response lists detailed metadata for all Worker and Edge Nodes that the Leader manages. Use the `id` value for the desired Node as the `nodeId` in the request URL.

For example, to send a request to the `GET /health` endpoint for the Worker Node `abc123a9-ea69-4066-b295-456defb55784`, the complete URL is:

{{% tabs "cloud" "cloud" "Cribl.Cloud and Hybrid Example (Worker/Edge Node)" "on-prem" "On-Prem Example (Worker/Edge Node)" %}}
{{% tab-item "cloud" %}}

```
https://${workspaceName}-${organizationId}.cribl.cloud/api/v1/w/abc123a9-ea69-4066-b295-456defb55784/health
```

{{% /tab-item %}}
{{% tab-item "on-prem" %}}

```
https://${hostname}:${port}/api/v1/w/abc123a9-ea69-4066-b295-456defb55784/health
```

{{% /tab-item %}}
{{% /tabs %}}

#### Cribl Search Context {#base-url-cribl-search}

For [Cribl Search endpoints](https://docs.cribl.io/cribl-as-code/api-reference/control-plane/cribl-search), the base URL includes `/m` and `default_search`:

```
https://${workspaceName}-${organizationId}.cribl.cloud/api/v1/m/default_search
```

For example, for a request to the `GET /search/jobs/{id}` endpoint, the complete URL is:

```
https://${workspaceName}-${organizationId}.cribl.cloud/api/v1/m/default_search/search/jobs/{id}
```

### Management Plane Base URL {#mgmt-plane-base-url}

The management plane includes endpoints for administrative tasks like configuring and managing Workspaces. The management plane is supported for Cribl.Cloud only.

For [management plane endpoints](https://docs.cribl.io/cribl-as-code/api-reference/management-plane/), the base URL is:

```
https://gateway.cribl.cloud
```

For example, for a request to the `GET /v1/organizations/{organizationId}/workspaces` endpoint, the complete URL is:

```
https://gateway.cribl.cloud/v1/organizations/${organizationId}/workspaces
```

## Path Parameters

Many Cribl API endpoints require to you provide path parameters. Most path parameters are used to specify individual resources. For example, in the endpoint `GET /pack/{id}`, the `{id}` identifies the specific Cribl Pack to retrieve.

For some endpoints, path parameters limit the scope of the request in some way. For example, in the endpoint `GET /products/{product}/groups`, the `{product}` path parameter indicates the Cribl product whose Worker Groups or Edge Fleets should be listed in the response. In another example, `GET /p/{pack}/pipelines`, the `{pack}` path parameter limits the response to Pipelines within the specified Pack.

The [API Reference](https://docs.cribl.io/api-reference/) identifies and describes the path parameters for each endpoint.

## Query Parameters

Some Cribl API endpoints support optional query parameters for filtering or modifying the response. For example, endpoints that return a list of objects can have lengthy responses, so they might support `limit` and `offset` query parameters to use for paginating the response. Other endpoints might support query parameters that allow you to specify additional properties to include in the response or a JavaScript expression to apply as a filter.

The [API Reference](https://docs.cribl.io/api-reference/) identifies and describes the supported query parameters for each endpoint.

## Request Size Limit

The size limit for requests to the Cribl API is 5 MB.

## Media Types

For endpoints that require a request body (typically `POST`, `PUT`, and `PATCH`), the server expects a valid `Content-Type` [request header](https://developer.mozilla.org/en-US/docs/Glossary/Request_header) that specifies the media type of the request body. In this example request, the `Content-Type` value is `application/json`:

```shell
curl --request POST \
--url "https://${workspaceName}-${organizationId}.cribl.cloud/api/v1/m/default_search/search/jobs" \
--header "Authorization: Bearer ${token}" \
--header "Content-Type: application/json" \
--data '{
  "query": "cribl dataset=\"goatherd_sample_dataset\" | limit 1000",
  "earliest": "-1h",
  "latest": "now",
  "sampleRate": 1
}'
```

If the request omits the `Content-Type` header or the value does not match the supported media type for the endpoint, the server might return an error.

For most `POST`, `PUT`, and `PATCH` endpoints in the Cribl API, the media type for the request body is `application/json`. Some endpoints support other media types, such as `application/x-ndjson` or `application/x-www-form-urlencoded`. The [API Reference](https://docs.cribl.io/api-reference/) specifies the supported media type for each endpoint in the **Request body** drop-down list.

![Location of the request body media type for an endpoint in the API Reference.](request-media-type-api-reference.png)
{border="true" caption="Endpoint's request body media type in API Reference"}

The [API Reference](https://docs.cribl.io/api-reference/) also specifies the media type for each endpoint's responses, which is helpful for ensuring proper data processing.

![Location of the response media type for an endpoint in the API Reference.](response-media-type-api-reference.png)
{border="true" caption="Endpoint's response media type in API Reference"}

## HTTP Status Codes

The Cribl API can return the following HTTP status codes in response headers:

| HTTP Status Code           | Meaning                                                                                                                                                  |
| -------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 200 OK                     | The request was successful.                                                                                                                              |
| 204 No Content             | The request was successful, but there is no content to send in the response. Often used for `DELETE` requests.                                           |
| 400 Bad Request            | The server could not understand the request due to malformed syntax or missing parameters.                                                               |
| 401 Unauthorized           | Authentication failed because credentials are missing or invalid.                                                                                        |
| 403 Forbidden              | The server understood the request but did not authorize it because permissions are insufficient to access the requested resource.                        |
| 404 Not Found              | The requested resource was not found. The endpoint may not exist or the resource may be unavailable.                                                     |
| 405 Method Not Allowed     | The request method is not supported for the resource (for example, a `POST` request for a resource that only supports `GET`).                            |
| 415 Unsupported Media Type | The server did not accept the request because the payload is in an unsupported data format. Often indicates that the `Content-Type` header is incorrect. |
| 420 Shutting Down          | The server is in the process of shutting down or is in standby.                                                                                          |
| 429 Too Many Requests      | The number of requests exceeds the `loginRateLimit` or `ssoRateLimit` setting.                                                                           |
| 500 Internal Server Error  | The server encountered an unexpected condition that prevented it from fulfilling the request.                                                            |
| 502 Bad Gateway            | While acting as a gateway or proxy, the server received an invalid response from the upstream server.                                                    |
| 503 Service Unavailable    | The server could not handle the request due to temporary overload or maintenance.                                                                        |

See the [MDN Web Docs](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status) for more information about HTTP status codes.
