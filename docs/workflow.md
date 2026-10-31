# Input:
- openAPI.json
- web crawler
- proxy capturing web crawler's traffic
# Processing:
- openAPI.json giving usable APIs
- Proxy traffic from web crawler can be used to infer role-session-object and possible business flow.
- standardized threat model giving ground truth.
### Example
Crawling under userA context
Accessible APIs including: `/item/1`, `/item/2`, `/item/3` as 200 code.
-> Infering `/item/<id>` for id from 4 to end:
 - returning 200 code: VULNERABLE
 - returning 403 code: VALID
Result will then be compared to threat model for evaluation