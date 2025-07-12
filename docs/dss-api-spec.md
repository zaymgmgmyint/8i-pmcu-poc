## 1.1 Instruction

To quickly understand the API capabilities offered by the VMS platform and expedite development, please follow the document content in the order provided below:

1. **Forward**  
   Explain the business capabilities and architecture of the VMS platform, and provide a preliminary understanding of the technical terms that will appear in the document.

2. **Overview**  
   Describe the open capabilities of the VMS platform and introduce integration solutions for different scenarios, providing a preliminary understanding of the integration process.

3. **Interface Specification**  
   Introduce the calling specifications for the VMS Open API and the MQ message-push specifications.

4. **API Interface**  
   Categorize the APIs for easy search, allowing developers to understand specific functions and usage methods through API descriptions and examples. Developers can then select the required API interfaces.

5. **MQ Notification Message**  
   Developers should pay attention to this section when they need to receive real-time notifications or alerts from the platform. Notifications are categorized for easy searching, with descriptions and examples, so developers can subscribe to the necessary topics.

6. **Best Practice**  
   Provide detailed integration methods for commonly used platform features through classic integration cases, enabling developers to gain a deeper understanding of how to use the platform API effectively.

7. **Appendix**  
   Include the data dictionary, error codes, and code-example demos for reference. Contains:
    - API login authentication demo
    - MQ docking demo
    - Encryption/decryption demo

## 1.4 Integration Process

1. **Authorize**  
   - `POST /brms/api/v1.0/accounts/authorize` → `401 Unauthorized`  
   - Retry `POST /brms/api/v1.0/accounts/authorize` → `200 OK`  

2. **Keep Alive**  
   - `POST /brms/api/v1.0/accounts/keepalive` → `200 OK`  

3. **Get MQ Config & Subscribe**  
   - `POST /brms/api/v1.0/BRM/Config/GetMqConfig` → `200 OK`  
   - Subscribe to MQ notifications  

4. **Business API Call**  
   - Call your Business API → `200 OK`


## 2.1 HTTP Interface Protocol Specification

All APIs provided by VMS are based on the HTTP/1.1 protocol and follow RESTful principles. Data exchanged is standardized in JSON format. VMS defaults to open HTTPS ports and does not recommend using HTTP for calls. To enable HTTP access, the allowlist for port 80 must be configured in VMS (System Parameters → Security Configuration → HTTP Allowlist).

| Item                        | Description                                                                                                                                                                            |
|-----------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Transmission Method**     | To ensure the security of transmission, uses HTTPS.                                                                                                                                     |
| **URL Format**              | `http(s)://[platform ip]:[platform port]/[subsystem]/api/[version]/[module]/[interface]/...`  
For details, see the rules of URL below.                                                                                              |
| **Request Method**          | `GET` / `POST` / `PUT` / `DELETE`                                                                                                                                                      |
| **Data Format**             | All request and response data are in JSON format.                                                                                                                                       |
| **Character Encoding**      | UTF-8                                                                                                                                                                                   |
| **Safety Authentication**   | Secured via username/password; only users who authenticate and obtain a token may call the API.                                                                                         |
| **Permission Control**      | Most APIs are gated by VMS menu permissions—unauthorized calls return an error.                                                                                                        |
| **Certificate Requirements**| None                                                                                                                                                                                    |
| **Calling Result**          | See “HTTP Returned Parameters” section for details on the API response format.                                                                                                         |


### 2.1.1 Request Instructions

#### Request Methods

| Request Method | Operation                                                                                                                   |
| -------------- | --------------------------------------------------------------------------------------------------------------------------- |
| **POST**       | Obtain resources, mostly used for business data query and data acquisition.                                                 |
| **GET**        | Resource creation and data submission, primarily used for sending data to the backend or inserting it into a database.     |
| **PUT**        | Resource updating, primarily used for refreshing backend caches, databases, etc.                                            |
| **DELETE**     | Resource deletion, primarily used for removing data records.                                                                |


### 2.1.2 Response Instructions

The status code of an HTTP interface call for success is always **200** (a **401** is returned for authentication failures). Business-level exceptions are signaled in the response body via the `code` and `desc` fields.

| Parameter | Type   | Description                                                                                                       |
|-----------|--------|-------------------------------------------------------------------------------------------------------------------|
| `code`    | int    | Error code: `1000` indicates success; any other value indicates failure. (See Appendix 6.2 for common error codes.) |
| `desc`    | string | Human-readable description of the status or error code.                                                            |
| `data`    | object | Result payload. Schema varies by interface.                                                                        |

#### Example 1: Successful response (no data)

```json
{
  "code": 1000,
  "desc": "Success",
  "data": null
}
```
```json
{
  "code": 1000,
  "desc": "Success",
  "data": {
    "doorGroupName": "b007",
    "timeTemplateId": "3",
    "channelIds": [
      "1000001570$0"
    ],
    "holidayPlanId": "0",
    "remark": "test"
  }
}
```

```json
{
  "code": 1004,
  "desc": "The parameter is illegal.",
  "data": null
}
```
````json
{
  "code": 10004,
  "desc": "The carNo is alresdy exists or repeat.",
  "data": {
    "repeatCarNos": [],
    "existingCarNos": ["JA2563D8"]
    }
}
````

## 2.2 Specification of MQ Message Subscription and Push

Notifications from the VMS platform are pushed in real time to clients or third parties via ActiveMQ. Developers must subscribe to the MQ message queue as needed according to VMS specifications to receive real-time notifications or alerts. The protocol body uses JSON format and is consistent for both sending and receiving queues.

### Request Parameter

| Parameter | Type   | Description      |
| --------- | ------ | ---------------- |
| `id`      | string | SN               |
| `method`  | string | Method           |
| `info`    | object | Message content  |

**Example of message body:**
```json
{
  "id": "112456",
  "method": "...",
  "info": {
    // ...
  }
}
```
Currently, the VMS platform has four topics that require subscription. The `userId` and `userGroupId` represent the ID of the logged-in user and the user group ID, respectively. The login authentication interface returns the current user’s `userId` and `userGroupId`. For example, if the current user’s `userId` is `1` and `userGroupId` is `2`, subscribe to:

| Parameter    | Topic Pattern                                                      | Example                                              |
|--------------|--------------------------------------------------------------------|------------------------------------------------------|
| Alarm topic  | `mq.alarm.msg.topic.{userId}`<br>`mq.alarm.msg.group.topic.{userGroupId}` | `mq.alarm.msg.topic.1`<br>`mq.alarm.msg.group.topic.2` |
| Event topic  | `mq.event.msg.topic.{userId}`                                      | `mq.event.msg.topic.1`                               |
| Public topic | `mq.common.msg.topic`                                              | `mq.common.msg.topic`                                |
