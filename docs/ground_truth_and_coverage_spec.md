# Tài Liệu Triển Khai Ground Truth Schema, Metrics Đo Lường Và Script Coverage

Tài liệu này quy định chi tiết cấu trúc **Ground Truth Schema**, **Bộ Chỉ Số Đo Lường (Metrics)** và **Mã Nguồn Script Python (`coverage_calculator.py`)** để kiểm tra độ bao phủ (Coverage) và độ chính xác của cơ chế Oracle trong hệ thống kiểm thử API an ninh dựa trên trạng thái (Stateful API Security Testing).

---

## 1. Ground Truth Schema (`ground_truth_schema.yaml`)

Ground Truth Schema đóng vai trò là "mẫu đối soát chuẩn" cho các kịch bản kiểm thử trong môi trường Cyber Range (ví dụ: OWASP crAPI). Schema định nghĩa mối quan hệ Actor–Object–State và danh sách các lỗ hổng đã được xác định trước.

```yaml
version: "1.0"
metadata:
  application_name: "crAPI-Benchmark"
  environment: "cyber-range-docker"
  openapi_spec_path: "./spec/openapi.json"

# 1. Định nghĩa vai trò, người dùng và tenant
actors:
  - id: "user_01"
    role: "customer"
    tenant: "tenant_A"
    session_token: "Bearer token_user_01_hash"
  - id: "user_02"
    role: "customer"
    tenant: "tenant_B"
    session_token: "Bearer token_user_02_hash"
  - id: "admin_01"
    role: "admin"
    tenant: "system"
    session_token: "Bearer token_admin_hash"

# 2. Định nghĩa đối tượng và quyền sở hữu (Object Ownership)
objects:
  - id: "order_101"
    type: "order"
    owner: "user_01"
    tenant: "tenant_A"
    initial_state: "CREATED"
  - id: "order_202"
    type: "order"
    owner: "user_02"
    tenant: "tenant_B"
    initial_state: "PAID"

# 3. Đồ thị trạng thái nghiệp vụ (Business State Graph)
business_states:
  entity: "order"
  valid_transitions:
    - from: "CREATED"
      to: "PAID"
      action: "POST /api/v1/orders/{id}/pay"
    - from: "PAID"
      to: "SHIPPED"
      action: "POST /api/v1/orders/{id}/ship"

# 4. Danh sách lỗ hổng Ground Truth (Dùng để tính Precision & Recall)
ground_truth_vulnerabilities:
  - id: "VULN-BOLA-01"
    type: "BOLA"
    owasp_category: "API1:2023"
    target_endpoint: "/api/v1/orders/{id}"
    http_method: "GET"
    target_object_id: "order_101"
    unauthorized_actor: "user_02"  # User_02 đọc đơn hàng của User_01
    expected_status_code: 403
    vulnerable_status_code: 200

  - id: "VULN-BFLA-01"
    type: "BFLA"
    owasp_category: "API5:2023"
    target_endpoint: "/api/v1/admin/users"
    http_method: "GET"
    unauthorized_role: "customer"  # Customer gọi API quản trị
    expected_status_code: 403
    vulnerable_status_code: 200

  - id: "VULN-STATE-01"
    type: "BUSINESS_LOGIC"
    owasp_category: "API6:2023"
    target_endpoint: "/api/v1/orders/{id}/ship"
    http_method: "POST"
    target_object_id: "order_101" # Chuyển từ CREATED -> SHIPPED khi chưa PAID
    invalid_state_before: "CREATED"
    expected_status_code: 400
    vulnerable_status_code: 200
```

---

## 2. Các Chỉ Số Đo Lường (Evaluation Metrics)

Hệ thống đánh giá được tổ chức thành 4 nhóm chỉ số cơ bản:

| Nhóm Metric | Tên Chỉ Số | Công Thức / Cách Tính | Ý Nghĩa Thực Tế |
| :--- | :--- | :--- | :--- |
| **Endpoint Coverage** | **Specification Coverage ($C_{ep}$)** | $\frac{\text{Số Endpoint/Method đã gọi}}{\text{Tổng Endpoint/Method trong OpenAPI Spec}} \times 100\%$ | Đo lường mức độ phủ đường dẫn công khai của API. |
| **Role-Matrix Coverage** | **Cross-Role Access Coverage ($C_{role}$)** | $\frac{\text{Số cặp (Actor, Object\_Owner, Action) đã test}}{\text{Tổng số giao điểm trong Role Matrix}} \times 100\%$ | Đảm bảo kiểm thử đầy đủ các ma trận phân quyền chéo (ngang và dọc). |
| **State Coverage** | **State Transition Coverage ($C_{state}$)** | $\frac{\text{Số cạnh (State\_A } \rightarrow \text{ State\_B) được duyệt}}{\text{Tổng số cạnh hợp lệ/bất hợp lệ trong Graph}} \times 100\%$ | Đánh giá mức độ quét qua các luồng trạng thái nghiệp vụ. |
| **Flaw Detection Accuracy** | **Precision ($P$)**<br>**Recall / Detection Rate ($R$)**<br>**False Positive Rate ($FPR$)** | $P = \frac{TP}{TP + FP}$<br>$R = \frac{TP}{TP + FN}$<br>$FPR = \frac{FP}{FP + TN}$ | Đánh giá độ chính xác của Oracle xác định và tỷ lệ bỏ sót lỗ hổng thực tế. |

---

## 3. Script Python Tính Toán Coverage & Oracle Accuracy (`coverage_calculator.py`)

Dưới đây là mã nguồn Python xử lý phân tích file OpenAPI Spec, Ground Truth Schema và Log thực thi (Replay Logs) để tự động xuất báo cáo đánh giá:

```python
import json
import yaml
from typing import Dict, List, Set, Any

class StatefulCoverageCalculator:
    def __init__(self, openapi_spec_dict: Dict[str, Any], ground_truth_dict: Dict[str, Any]):
        self.openapi_spec = openapi_spec_dict
        self.ground_truth = ground_truth_dict
        self.spec_endpoints = self._extract_spec_endpoints()
        self.ground_truth_vulns = self.ground_truth.get("ground_truth_vulnerabilities", [])

    def _extract_spec_endpoints(self) -> Set[str]:
        """Trích xuất tất cả các cặp (HTTP_METHOD, PATH) từ OpenAPI spec."""
        endpoints = set()
        paths = self.openapi_spec.get("paths", {})
        for path, methods in paths.items():
            for method in methods.keys():
                if method.lower() in ["get", "post", "put", "delete", "patch"]:
                    endpoints.add(f"{method.upper()} {path}")
        return endpoints

    def evaluate_execution_logs(self, execution_logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        executed_endpoints = set()
        tested_role_matrix_pairs = set()
        detected_vuln_ids = set()
        reported_candidates = 0

        for log in execution_logs:
            # 1. Đo lường Endpoint Coverage
            method = log.get("method", "").upper()
            endpoint = log.get("endpoint", "")
            if method and endpoint:
                executed_endpoints.add(f"{method} {endpoint}")

            # 2. Đo lường Role-Matrix Coverage
            actor_role = log.get("actor_role")
            target_owner_role = log.get("target_object_owner_role")
            action = log.get("action")
            if actor_role and target_owner_role and action:
                tested_role_matrix_pairs.add((actor_role, target_owner_role, action))

            # 3. Đánh giá Oracle Verdict & Ground Truth Matching
            if log.get("oracle_verdict") == "VULNERABILITY_DETECTED":
                reported_candidates += 1
                matched_id = log.get("matched_ground_truth_id")
                if matched_id:
                    detected_vuln_ids.add(matched_id)

        # Tính phần trăm độ bao phủ
        total_spec = len(self.spec_endpoints)
        executed_count = len(executed_endpoints)
        endpoint_coverage_pct = (executed_count / total_spec * 100) if total_spec > 0 else 0.0

        # Tính Precision / Recall dựa trên Ground Truth
        total_gt = len(self.ground_truth_vulns)
        tp = len(detected_vuln_ids) # True Positives
        fp = max(0, reported_candidates - tp) # False Positives
        fn = max(0, total_gt - tp) # False Negatives

        recall = (tp / total_gt * 100) if total_gt > 0 else 0.0
        precision = (tp / reported_candidates * 100) if reported_candidates > 0 else 0.0

        return {
            "endpoint_coverage": {
                "total_endpoints_in_spec": total_spec,
                "executed_endpoints_count": executed_count,
                "coverage_percentage": round(endpoint_coverage_pct, 2),
                "uncovered_endpoints": list(self.spec_endpoints - executed_endpoints)
            },
            "role_matrix_coverage": {
                "unique_access_pairs_tested": len(tested_role_matrix_pairs),
                "tested_pairs": [f"Actor:{r} -> Owner:{o} | Action:{a}" for r, o, a in tested_role_matrix_pairs]
            },
            "oracle_accuracy": {
                "total_ground_truth_vulnerabilities": total_gt,
                "true_positives_detected": tp,
                "false_positives": fp,
                "false_negatives": fn,
                "recall_percentage": round(recall, 2),
                "precision_percentage": round(precision, 2),
                "detected_vulnerability_ids": list(detected_vuln_ids)
            }
        }

# --- Kịch bản chạy thử nghiệm (Demo Execution) ---
if __name__ == "__main__":
    mock_spec = {
        "paths": {
            "/api/v1/orders/{id}": {"get": {}, "post": {}},
            "/api/v1/orders/{id}/ship": {"post": {}},
            "/api/v1/admin/users": {"get": {}}
        }
    }

    mock_gt = {
        "ground_truth_vulnerabilities": [
            {"id": "VULN-BOLA-01", "endpoint": "/api/v1/orders/{id}", "method": "GET"},
            {"id": "VULN-BFLA-01", "endpoint": "/api/v1/admin/users", "method": "GET"}
        ]
    }

    mock_logs = [
        {
            "method": "GET",
            "endpoint": "/api/v1/orders/{id}",
            "actor_role": "customer",
            "target_object_owner_role": "customer_other",
            "action": "READ",
            "oracle_verdict": "VULNERABILITY_DETECTED",
            "matched_ground_truth_id": "VULN-BOLA-01"
        },
        {
            "method": "POST",
            "endpoint": "/api/v1/orders/{id}",
            "actor_role": "customer",
            "target_object_owner_role": "self",
            "action": "CREATE",
            "oracle_verdict": "PASS"
        }
    ]

    calculator = StatefulCoverageCalculator(mock_spec, mock_gt)
    report = calculator.evaluate_execution_logs(mock_logs)
    print(json.dumps(report, indent=2))
```

---

## 4. Kết Quả Báo Cáo Đầu Ra Mẫu (Sample JSON Output)

```json
{
  "endpoint_coverage": {
    "total_endpoints_in_spec": 4,
    "executed_endpoints_count": 2,
    "coverage_percentage": 50.0,
    "uncovered_endpoints": [
      "GET /api/v1/admin/users",
      "POST /api/v1/orders/{id}/ship"
    ]
  },
  "role_matrix_coverage": {
    "unique_access_pairs_tested": 2,
    "tested_pairs": [
      "Actor:customer -> Owner:customer_other | Action:READ",
      "Actor:customer -> Owner:self | Action:CREATE"
    ]
  },
  "oracle_accuracy": {
    "total_ground_truth_vulnerabilities": 2,
    "true_positives_detected": 1,
    "false_positives": 0,
    "false_negatives": 1,
    "recall_percentage": 50.0,
    "precision_percentage": 100.0,
    "detected_vulnerability_ids": [
      "VULN-BOLA-01"
    ]
  }
}
```
