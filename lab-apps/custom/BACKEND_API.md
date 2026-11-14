# Backend API local để kiểm thử

Backend này được dựng dựa trên hợp đồng API ở `docs/app1/openapi.json` (44 đường dẫn). Nó dùng FastAPI và MongoDB, đóng gói bằng Docker Compose. Các endpoint được ghép với đường dẫn trong OpenAPI; dữ liệu tạo mới được lưu lại trong MongoDB.

## Chạy dịch vụ

Yêu cầu: Docker và Docker Compose.

```sh
docker compose up --build
```

- Swagger UI: <http://localhost:8000/docs>
- OpenAPI gốc: <http://localhost:8000/openapi-source.json>
- Health check: <http://localhost:8000/health>
- API: `http://localhost:8000/api/v1/...`
- MongoDB từ máy host: `mongodb://localhost:27017`, database `inlanefreight_api`

Dừng container: `docker compose down`. Xoá cả dữ liệu test: `docker compose down -v`.

## Thử nhanh

Tạo customer (command DTO được bọc trong `NewCustomer` theo OpenAPI):

```sh
curl -X POST http://localhost:8000/api/v1/customers \
  -H 'Content-Type: application/json' \
  -d '{"NewCustomer":{"Name":"Demo Customer","Email":"demo@example.test","PhoneNumber":"0900000000","BirthDate":"2000-01-01","Password":"demo"}}'
```

API trả về `ID`. Liệt kê customers và lấy chi tiết bằng ID:

```sh
curl http://localhost:8000/api/v1/customers
curl http://localhost:8000/api/v1/customers/ID_TRA_VE
```

Đăng nhập bằng email/password vừa tạo:

```sh
curl -X POST http://localhost:8000/api/v1/authentication/customers/sign-in \
  -H 'Content-Type: application/json' \
  -d '{"Email":"demo@example.test","Password":"demo"}'
```

Token customer/supplier của mock cũ được trả dưới dạng `Token`, dùng `Authorization: Bearer <Token>` với các route `current-user`.

## Custom authorization/workflow lab

Mock có thêm target thử nghiệm riêng ở `/lab/v1` để chạy các case BOLA, BFLA, BOPLA, tenant isolation và workflow. Tài khoản synthetic:

| Vai trò | Email | Mật khẩu |
| --- | --- | --- |
| Customer, tenant A | `customer-a@lab.test` | `lab123` |
| Customer thứ hai, tenant A | `customer-a2@lab.test` | `lab123` |
| Customer, tenant B | `customer-b@lab.test` | `lab123` |
| Support, tenant A | `support-a@lab.test` | `lab123` |
| Admin | `admin-a@lab.test` | `lab123` |

Lấy token riêng cho actor:

```sh
curl -X POST http://localhost:8000/__lab/auth/token \
  -H 'Content-Type: application/json' \
  -d '{"Email":"customer-a@lab.test","Password":"lab123"}'
```

Sau đó gọi `GET /lab/v1/resources` hoặc `GET /lab/v1/resources/{resource_id}` với `Authorization: Bearer <Token>`. Safe mode là mặc định: actor chỉ đọc tài nguyên được phép, role/property bị kiểm tra, workflow sai trạng thái bị từ chối. Các lab route cũng được thêm vào Swagger/OpenAPI.

Để bật một planted case, truyền flag của case lúc khởi động lại API, ví dụ:

```sh
LAB_VULNERABILITIES=AUTHZ-001 docker compose up -d --force-recreate api
```

Để quay về safe mode:

```sh
LAB_VULNERABILITIES= docker compose up -d --force-recreate api
```

`app/cyber-range/flaw_catalog.yaml` mô tả từng flaw theo endpoint, actor, oracle và evidence của taxonomy; catalog được đối chiếu với route trong `app/main.py` và `app/lab_extensions.py`. `app/cyber-range/ground_truth/ground_truth.yaml` lưu fixture replay/scoring: 30 planted case và 8 benign case. Ba mươi planted case đã được replay trên API ở safe mode và lần lượt bật từng flag; kết quả, trạng thái và readback được ghi trong ground truth. `family` dùng taxonomy F1–F5 trong `docs/Taxonomy/families.yaml`; flag mặc định tắt; `lab_ground_truth` không được expose qua API target. Request/response hashes, actor, operation, case ID, workflow ID, sequence ID, step index và state evidence được ghi vào `http_audit_events`.

Ba trace JSON có sẵn trong `app/cyber-range/traces/`. Chạy từ thư mục `app/` bằng `python runtrace.py --scenario cyber-range/traces/<trace>.json`; runner gửi toàn bộ sequence qua Safety Gateway và gắn metadata sequence vào audit log. Trace tài chính và ticket có state change, nên reset fixture trước mỗi lần replay. Chi tiết về case mapping, family counts và evidence contract nằm trong [`../../docs/GroundTruth_Metrics_Coverage.md`](../../docs/GroundTruth_Metrics_Coverage.md).

Reset toàn bộ seed mock (bao gồm lab sessions) chỉ hoạt động khi bật `LAB_MODE=true` và đặt secret `LAB_ADMIN_TOKEN`; gọi `POST /__lab/reset` với header `X-Lab-Admin-Token`. Mặc định reset bị khóa. Có thể truyền `LAB_MODE` và `LAB_ADMIN_TOKEN` qua environment khi chạy Compose.

## Lưu trữ

MongoDB collections được tách theo tài nguyên chính: customers, suppliers, supplier companies, products, orders, order items, payment options, billing addresses, báo cáo và discounts. Khi API khởi động, bộ seed được nạp tự động một lần theo từng ID cố định. Khởi động lại container không ghi đè thay đổi do bạn thực hiện. Volume `mongo_data` giữ dữ liệu khi container dừng.

Tài khoản mẫu để sign-in:

| Vai trò | Email | Mật khẩu |
| --- | --- | --- |
| Customer | `linh@example.test` | `demo123` |
| Customer | `minh@example.test` | `demo123` |
| Supplier | `supplier@example.test` | `demo123` |

Seed gồm customers, supplier/company, products, discounts, orders/items, payment options, billing addresses và quarterly/yearly reports. Có thể tắt nạp seed bằng cách đặt `SEED_DEMO_DATA=false` trong service `api` ở `docker-compose.yml`.

## Phạm vi mô phỏng

Spec mô tả endpoint, tham số và DTO nhưng không chứa bộ dữ liệu kết quả mẫu; bộ seed trong `app/seed.py` là dữ liệu demo do dự án tạo để bạn thử GET ngay. Backend hỗ trợ CRUD JSON thông dụng, multipart upload lưu nội dung file dạng Base64, đăng nhập local và OTP/reset mô phỏng. Đây là backend phục vụ kiểm thử tích hợp đường dẫn và lưu trữ; chưa tái tạo đầy đủ kiểm tra quyền theo role, quy tắc nghiệp vụ, định dạng mọi response hay dịch vụ gửi email/SMS của API gốc.
