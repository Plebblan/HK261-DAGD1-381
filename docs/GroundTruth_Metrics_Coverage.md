# Phần việc của Bac: Ground Truth Schema, Metrics & Script kiểm đếm Coverage

> **Dự án:** AI-Assisted Stateful Web/API Security Testing System
> **Giai đoạn:** Phase 1 – W5–W6 (10/2026) | **Vai trò:** Xuan Bac – data, ranking model, metrics, ablation, phân tích kết quả
> **Phục vụ KPI:** Workflow coverage ≥ 70% · Role/object-pair coverage ≥ 60% · Provenance/raw hash ≥ 95% · ≥ 20 planted cases có ground truth

---

## 1. Phạm vi công việc

| # | Công việc | Đầu ra | Phụ thuộc |
|---|---|---|---|
| B1 | Thiết kế schema ground truth (planted cases) | `ground_truth/planted_cases.csv` + `schema/ground_truth.schema.json` | Flaw cards từ Vu |
| B2 | Chuẩn hóa cấu trúc dữ liệu cho model, workflow, object seed, execution log | `model/rso.yaml`, `workflows/workflows.yaml`, `seed/objects.json`, `logs/executions.jsonl` | Range của Duc An |
| B3 | Định nghĩa công thức metrics (mẫu số, tử số, điều kiện "valid") | Mục 4 của tài liệu này | B1, B2 |
| B4 | Script kiểm đếm coverage ban đầu | `scripts/coverage.py` | B2, B3 |
| B5 | Quy tắc đóng băng ground truth/metrics | Mục 7 | Toàn nhóm |

**Nguyên tắc xuyên suốt (theo đề cương):** không đổi ground truth hay metrics sau khi đã xem kết quả test; mọi con số phải tái lập được từ seed + log.

---

## 2. Cấu trúc thư mục đề xuất

```
cyber-range/
├── model/
│   └── rso.yaml                # Actor – Resource – Action – State (mẫu số cho operation/pair coverage)
├── workflows/
│   └── workflows.yaml          # Danh sách workflow và thứ tự step (mẫu số cho workflow coverage)
├── seed/
│   └── objects.json            # Object được seed: id, type, owner, tenant (mẫu số cho pair coverage)
├── ground_truth/
│   └── planted_cases.csv       # Danh sách lỗi đã cài + case benign
├── schema/
│   └── ground_truth.schema.json
├── logs/
│   └── executions.jsonl        # Mỗi dòng = một request đã thực thi
├── scripts/
│   └── coverage.py
└── reports/
    └── coverage_report.json
```

---

## 3. Schema dữ liệu

### 3.1 Ground truth – `planted_cases.csv`

| Cột | Kiểu | Bắt buộc | Mô tả |
|---|---|---|---|
| `case_id` | string | ✔ | ID duy nhất, dạng `<FAMILY>-<NN>` (vd `BOLA-01`) |
| `app` | string | ✔ | App chứa lỗi (vd `custom_shop`, `crapi`) |
| `family` | enum | ✔ | `BOLA`, `BFLA`, `BOPLA`, `TENANT`, `WORKFLOW` |
| `op_id` | string | ✔ | Operation liên quan (khớp `actions[].id` trong `rso.yaml`) |
| `method` / `path` | string | ✔ | HTTP method và path template |
| `attacker` | string | ✔ | Actor thực hiện hành vi vi phạm |
| `victim` | string | | Actor/tenant sở hữu object (rỗng nếu BFLA thuần) |
| `object_id` | string | | Object bị tác động (nếu có) |
| `oracle_type` | enum | ✔ | `differential_authz`, `role_matrix`, `state_invariant`, `property_diff` |
| `expected_safe` | string | ✔ | Response an toàn kỳ vọng (vd `403`, `404`, `400`, `field_ignored`) |
| `observed_vulnerable` | string | ✔ | Hành vi khi lỗi được bật (vd `200 + data của victim`) |
| `flag` | string | ✔ | Cờ bật/tắt lỗi trong app (vd `BOLA_01`) |
| `is_benign` | bool | ✔ | `true` nếu là case KHÔNG có lỗi (đo false positive) |
| `cwe` | string | ✔ | vd `CWE-639` |
| `owasp` | string | ✔ | vd `API1:2023` |
| `split` | enum | ✔ | `dev` hoặc `heldout` – **chốt một lần, không đổi** |
| `evidence_required` | string | ✔ | Bằng chứng cần có để tính là finding hợp lệ (vd `replay + before/after`) |
| `verified_by` | string | ✔ | Người verify (khác người cài lỗi) |
| `verified_at` | date | ✔ | Ngày verify |

**Ràng buộc kiểm tra tự động (nên viết thành test):**

- `case_id` không trùng; `op_id` tồn tại trong `rso.yaml`; `attacker`/`victim` tồn tại trong `actors`.
- Mỗi `family` có ≥ 3 case; tổng ≥ 20; có ít nhất vài case `is_benign = true`.
- Phân chia `split`: theo **app hoặc scenario**, không trộn cùng scenario vào cả dev và heldout.
- `verified_by` ≠ người cài lỗi.

### 3.2 Model – `model/rso.yaml` (trích phần dùng cho metrics)

```yaml
tenants: [tenant_a, tenant_b]
actors:
  - {id: alice, role: customer, tenant: tenant_a}
  - {id: bob,   role: customer, tenant: tenant_b}
  - {id: carol, role: manager,  tenant: tenant_a}
  - {id: root,  role: admin,    tenant: platform}
actions:                        # mẫu số cho operation coverage
  - {id: create_order, method: POST, path: /orders}
  - {id: get_order,    method: GET,  path: "/orders/{id}"}
  - {id: pay_order,    method: POST, path: "/orders/{id}/pay"}
```

### 3.3 Workflow – `workflows/workflows.yaml`

```yaml
workflows:
  - id: WF_PURCHASE
    steps: [create_order, submit_order, pay_order, ship_order]
  - id: WF_REFUND
    steps: [create_order, pay_order, approve_refund]
```

### 3.4 Object seed – `seed/objects.json`

```json
[
  {"id": "order_1", "type": "order", "owner": "alice", "tenant": "tenant_a"},
  {"id": "order_2", "type": "order", "owner": "bob",   "tenant": "tenant_b"},
  {"id": "order_3", "type": "order", "owner": "carol", "tenant": "tenant_a"}
]
```

### 3.5 Execution log – `logs/executions.jsonl` (mỗi dòng một request)

| Trường | Mô tả |
|---|---|
| `run_id`, `seed` | Định danh lần chạy và seed (để tái lập, báo cáo theo ≥ 10 seeds ở Phase 2) |
| `sequence_id`, `step_idx` | Request thuộc sequence nào, ở vị trí nào |
| `op_id` | Khớp `actions[].id` |
| `actor`, `object_id` | Ai gọi, lên object nào |
| `status` | HTTP status |
| `valid_request` | `true` nếu request hợp lệ về cú pháp + precondition và tới được logic nghiệp vụ (xem 4.1) |
| `raw_hash` | Hash request/response thô (provenance) |
| `case_id` | (tuỳ chọn) nếu request là một probe cho planted case |
| `timestamp`, `before_state_hash`, `after_state_hash` | Bổ sung khi evidence schema hoàn thiện (W7–W9) |

```json
{"run_id":"r1","seed":1,"sequence_id":"s2","step_idx":0,"op_id":"get_order","actor":"bob","object_id":"order_1","status":403,"valid_request":true,"raw_hash":"b1","case_id":"BOLA-01"}
```

> Lưu ý: một probe authz mà server trả `403` vẫn là `valid_request = true` (request hợp lệ, bị từ chối đúng). `valid_request = false` chỉ dành cho request lỗi cú pháp, thiếu precondition, hoặc không tới được logic (vd `400` do sai schema, `404` do object chưa tồn tại).

---

## 4. Định nghĩa Metrics

### 4.1 Quy ước "valid"

Một request được tính là **valid** khi: (i) đúng schema/cú pháp, (ii) precondition của action được thỏa, (iii) request thực sự tới được logic nghiệp vụ (kể cả khi kết quả là bị từ chối đúng). Cờ này do **harness** ghi, không do script coverage tự suy đoán.

### 4.2 Metrics Phase 1

| Metric | Công thức | Mẫu số lấy từ | Ngưỡng |
|---|---|---|---|
| **Endpoint-operation coverage** | `\|ops có ≥1 request valid\| / \|ops\|` | `rso.yaml → actions` | báo cáo |
| **Workflow coverage** | `\|workflow được chạy đủ step, đúng thứ tự, trong 1 sequence valid\| / \|workflows\|` | `workflows.yaml` | **≥ 70%** |
| **Role/object-pair coverage** | `\|(actor, object) cross-tested valid\| / \|(actor, object) với actor ≠ owner\|` | `actors × objects` | **≥ 60%** |
| **Valid-sequence rate** | `\|sequence mà mọi step valid\| / \|sequence\|` | log | báo cáo |
| **Provenance rate** | `\|request có raw_hash\| / \|request\|` | log | **≥ 95%** |
| **Planted-case coverage** | `\|case_id được probe ít nhất 1 lần\| / \|planted cases\|` (theo family) | `planted_cases.csv` | báo cáo |
| **Safety-gate violations** | Số request ngoài allowlist / crash không phục hồi | audit log | **= 0** |

**Ghi chú về mẫu số role/object-pair:** bản ban đầu dùng toàn bộ `actors × objects` loại trừ cặp owner. Khi model trưởng thành, nên thu hẹp mẫu số vào các cặp **có ý nghĩa** (action áp dụng được cho resource type đó), và ghi rõ thay đổi này ở M1/M2 — **trước** khi xem kết quả.

### 4.3 Metrics dự kiến cho Phase 2 (chốt công thức sớm để không đổi sau)

| Metric | Công thức |
|---|---|
| Post-triage precision | `valid findings (human-verified) / reported candidates` (mục tiêu ≥ 0.85) |
| Recall theo family | `planted flaws phát hiện / planted flaws của family đó` |
| Precision@budget | Precision khi cố định số request tối đa `B` (so với baseline mạnh nhất, mục tiêu +20%) |
| Requests per valid finding | `tổng request / valid findings` |
| Triage time per valid finding | `tổng thời gian triage / valid findings` (mục tiêu giảm ≥ 25%) |
| False-positive rate | Tính trên cả case benign |
| State-reset failures | Số lần hash trạng thái sau reset ≠ hash chuẩn |

Thống kê: chạy ≥ 10 seeds/configurations; báo cáo mean/median, SD/IQR, bootstrap 95% CI.

---

## 5. Script kiểm đếm coverage ban đầu

**Cài đặt:** Python 3.9+, `pip install pyyaml`.

**Chạy:**

```bash
python scripts/coverage.py \
  --model model/rso.yaml \
  --workflows workflows/workflows.yaml \
  --objects seed/objects.json \
  --log logs/executions.jsonl \
  --cases ground_truth/planted_cases.csv \
  --out reports/coverage_report.json
```

**Mã nguồn (`scripts/coverage.py`):**

```python
#!/usr/bin/env python3
"""coverage.py - Script kiem dem coverage ban dau cho Cyber Range (Phase 1).

Doc: model/rso.yaml, workflows/workflows.yaml, seed/objects.json, logs/executions.jsonl
Tinh: operation coverage, workflow coverage, role-object pair coverage,
      valid-sequence rate, provenance rate, planted-case coverage.
"""
import argparse, csv, json, sys
from pathlib import Path
import yaml

KPI = {"workflow_coverage": 0.70, "role_object_pair_coverage": 0.60, "provenance_rate": 0.95}


def load_jsonl(path):
    rows = []
    with open(path, encoding="utf-8") as f:
        for ln, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as e:
                sys.exit(f"[loi] {path}:{ln} JSON khong hop le: {e}")
    return rows


def ratio(a, b):
    return round(a / b, 4) if b else 0.0


def operation_coverage(ops, log):
    covered = {r["op_id"] for r in log if r.get("valid_request") and r["op_id"] in ops}
    return covered, ratio(len(covered), len(ops))


def workflow_coverage(workflows, log):
    """Workflow duoc phu khi MOT sequence_id chua du cac step theo dung thu tu, deu valid."""
    by_seq = {}
    for r in sorted(log, key=lambda x: (x["sequence_id"], x.get("step_idx", 0))):
        if r.get("valid_request"):
            by_seq.setdefault(r["sequence_id"], []).append(r["op_id"])
    covered = set()
    for wf in workflows:
        steps = wf["steps"]
        for seq in by_seq.values():
            it = iter(seq)
            if all(s in it for s in steps):  # kiem tra subsequence theo thu tu
                covered.add(wf["id"])
                break
    return covered, ratio(len(covered), len(workflows))


def pair_universe(actors, objects):
    """Cap cross-tested: actor khac owner cua object."""
    return {(a["id"], o["id"]) for a in actors for o in objects if o["owner"] != a["id"]}


def pair_coverage(actors, objects, log):
    universe = pair_universe(actors, objects)
    covered = {(r["actor"], r["object_id"]) for r in log
               if r.get("valid_request") and (r.get("actor"), r.get("object_id")) in universe}
    return universe, covered, ratio(len(covered), len(universe))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--workflows", required=True)
    ap.add_argument("--objects", required=True)
    ap.add_argument("--log", required=True)
    ap.add_argument("--cases", help="ground_truth/planted_cases.csv (tuy chon)")
    ap.add_argument("--out", default="coverage_report.json")
    a = ap.parse_args()

    model = yaml.safe_load(Path(a.model).read_text(encoding="utf-8"))
    workflows = yaml.safe_load(Path(a.workflows).read_text(encoding="utf-8"))["workflows"]
    objects = json.loads(Path(a.objects).read_text(encoding="utf-8"))
    log = load_jsonl(a.log)

    ops = {x["id"] for x in model["actions"]}
    actors = model["actors"]

    op_cov, op_ratio = operation_coverage(ops, log)
    wf_cov, wf_ratio = workflow_coverage(workflows, log)
    universe, pair_cov, pair_ratio = pair_coverage(actors, objects, log)

    seqs = {}
    for r in log:
        seqs.setdefault(r["sequence_id"], []).append(r)
    valid_seq = sum(1 for s in seqs.values() if all(x.get("valid_request") for x in s))
    prov = sum(1 for r in log if r.get("raw_hash"))

    report = {
        "n_log_rows": len(log), "n_sequences": len(seqs),
        "operation_coverage": op_ratio,
        "operations_uncovered": sorted(ops - op_cov),
        "workflow_coverage": wf_ratio,
        "workflows_uncovered": sorted({w["id"] for w in workflows} - wf_cov),
        "role_object_pair_coverage": pair_ratio,
        "pairs_total": len(universe), "pairs_covered": len(pair_cov),
        "valid_sequence_rate": ratio(valid_seq, len(seqs)),
        "provenance_rate": ratio(prov, len(log)),
    }

    if a.cases:
        with open(a.cases, newline="", encoding="utf-8") as f:
            cases = list(csv.DictReader(f))
        touched = {r.get("case_id") for r in log if r.get("case_id")}
        report["planted_cases_total"] = len(cases)
        report["planted_cases_touched"] = len({c["case_id"] for c in cases} & touched)
        by_fam = {}
        for c in cases:
            by_fam.setdefault(c["family"], [0, 0])
            by_fam[c["family"]][0] += 1
            by_fam[c["family"]][1] += c["case_id"] in touched
        report["cases_by_family"] = {k: {"total": v[0], "touched": v[1]} for k, v in by_fam.items()}

    report["kpi_check"] = {k: ("PASS" if report[k] >= t else "FAIL") for k, t in KPI.items()}

    Path(a.out).write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
```

### 5.1 Kết quả chạy thử trên dữ liệu mẫu

Với dữ liệu mẫu ở mục 3 (4 actor, 3 object, 6 operation, 2 workflow, 6 dòng log), script cho kết quả đúng như tính tay:

| Metric | Kết quả | Giải thích |
|---|---|---|
| Operation coverage | 0.8333 (5/6) | `approve_refund` chưa được gọi valid |
| Workflow coverage | 0.5 (1/2) | `WF_PURCHASE` đủ 4 step trong `s1`; `WF_REFUND` thiếu |
| Role/object-pair coverage | 0.1111 (1/9) | Universe = 4×3 − 3 cặp owner = 9; mới có `bob → order_1` |
| Valid-sequence rate | 0.6667 | `s3` có request invalid |
| Provenance rate | 0.8333 | 1 dòng thiếu `raw_hash` |
| Planted cases touched | 1/4 | Mới probe `BOLA-01` |

Đây chỉ là dữ liệu mẫu để xác nhận script hoạt động; số liệu thật sẽ có khi harness chạy trên range.

### 5.2 Giới hạn của bản ban đầu (cần cải tiến ở W7+)

- Chưa tách theo `app` và theo `seed` (cần để báo cáo mean/SD qua nhiều seed).
- Pair coverage chưa lọc theo tính áp dụng của action lên resource type.
- Workflow coverage chỉ kiểm tra thứ tự step trong một sequence, chưa kiểm tra ràng buộc dữ liệu giữa các step (vd cùng `object_id`).
- Chưa tính coverage theo `tenant` (cross-tenant pairs) riêng.
- Chưa đọc audit log của Safety Gateway để tính safety violations.

---

## 6. Kế hoạch theo tuần

### W5
- [ ] Chốt cột và kiểu dữ liệu của `planted_cases.csv` cùng Vu và Duc An
- [ ] Viết JSON Schema + test ràng buộc (mục 3.1)
- [ ] Chốt định nghĩa `valid_request` với Duc An (harness ghi cờ này)
- [ ] Soạn `workflows.yaml` và `objects.json` khớp với range
- [ ] Hoàn thiện công thức metrics (mục 4) và gửi nhóm review

### W6
- [ ] Chạy `coverage.py` trên log của smoke test từ range thật
- [ ] Đối chiếu số liệu với tính tay để xác nhận script đúng
- [ ] Điền đủ ≥ 20 case vào ground truth cùng Vu (verify độc lập)
- [ ] Chốt `split` dev/heldout, ghi lại và đóng băng
- [ ] Xuất `coverage_report.json` đầu tiên + chuẩn bị 1–2 trang cho M2 review

---

## 7. Quy tắc đóng băng và tính khoa học

1. **Chốt trước khi xem kết quả:** công thức metrics, mẫu số, và `split` dev/heldout được ghi vào git (tag, ví dụ `gt-v1`) trước khi chạy đánh giá.
2. **Mọi thay đổi sau đó** phải có version mới và lý do bằng văn bản; không ghi đè bản cũ.
3. **Người cài lỗi ≠ người verify** ground truth.
4. **Case benign** phải có đủ để đo false positive một cách có ý nghĩa.
5. **KPI trượt vẫn có thể được chấp nhận** nếu artifact tái lập được và có phân tích nguyên nhân/giới hạn khái quát hóa (nguyên tắc nghiệm thu của đề cương).

---

## 8. Checklist nghiệm thu phần của Bac (cuối W6)

- [ ] `planted_cases.csv` ≥ 20 dòng, đủ 5 family, có case benign, qua bộ test ràng buộc
- [ ] JSON Schema + test validate chạy được
- [ ] Công thức metrics có văn bản, mẫu số khớp `rso.yaml`/`workflows.yaml`/`objects.json`
- [ ] `coverage.py` chạy được trên log thật và khớp tính tay
- [ ] Có `coverage_report.json` đầu tiên (kể cả khi chưa đạt KPI)
- [ ] Ground truth và `split` được tag phiên bản
- [ ] Danh sách giới hạn đã biết (mục 5.2) được ghi lại để xử lý ở W7+

---

## 9. Cyber Range hiện có trong `app/` (đối chiếu implementation)

Phần này cập nhật mô hình và phạm vi theo code đang có trong `app/main.py`, `app/lab_extensions.py`, `app/seed.py` và artifact dưới `cyber-range/`. Khi có khác biệt với ví dụ tổng quát ở các mục trước, dùng tên trường, ID, route và trạng thái ở phần này làm chuẩn cho **range hiện tại**. Các ví dụ `alice`, `get_order`, `WF_PURCHASE` ở mục 3 chỉ là ví dụ minh họa, không phải dữ liệu seed đang chạy.

### 9.1 Thành phần và cách khởi tạo

| Thành phần | Hiện trạng trong repository | Ý nghĩa với coverage |
|---|---|---|
| API | FastAPI, MongoDB; API mock theo OpenAPI cùng route `/lab/v1/*` | Ghi `app=custom_mock`; traffic range phải hướng vào local service |
| Actor và tenant | `cyber-range/model/rso.yaml`; 7 actor: customer, support, admin và supplier ở hai tenant | ID phân biệt hoa/thường và lấy nguyên văn từ artifact |
| Resource seed | `cyber-range/seed/objects.json`; 9 `lab_resources` và 6 fixture phụ cho invoice, payout, review | Các cặp actor-resource tính từ `ID`, `OwnerID`, `TenantID`; chỉ tính actor-resource có ý nghĩa theo role/resource/action |
| Workflow | `cyber-range/workflows/workflows.yaml`; 5 workflow cho order, ticket, invoice và payout | Mỗi step có operation, actor, object, precondition và postcondition; giữ cùng object qua các bước |
| Ground truth | `cyber-range/ground_truth/planted_cases.csv`; 28 planted cases và 8 benign cases | Tổng 36 dòng; 23 development, 5 held-out planted; benign hiện ở development |
| Runtime seed | `app/seed.py` nạp trực tiếp RSO, workflows, objects và CSV vào các collection `lab_*` | CSV/schema là nguồn ground truth; API status chỉ công bố số lượng, không trả nhãn chi tiết |
| Reset | `POST /__lab/reset`, yêu cầu `LAB_MODE`, `LAB_ADMIN_TOKEN` và client local/private | Reset đưa collection về seed; execution log cần ghi reset/run/seed để replay |

API phát hành token giả lập qua `POST /__lab/auth/token` bằng credential từ actor seed. Lỗ hổng mặc định tắt; bật có chọn lọc qua `LAB_VULNERABILITIES` (danh sách flag phân tách dấu phẩy, hoặc `*`). Ghi lại chính xác cấu hình flag cho mỗi run vì response 200 chỉ là bằng chứng có hành vi, không đủ để kết luận nếu không biết trạng thái cấu hình và before/after.

### 9.2 Bề mặt thao tác được cài trong range

| Nhóm | Route/mẫu route | Hành vi và liên hệ ground truth |
|---|---|---|
| Resource | `GET /lab/v1/resources`, `GET/PATCH/DELETE /lab/v1/resources/{resource_id}` | Đọc/list, cập nhật thuộc tính, xóa; AUTHZ-001–004, 007–012, 016–019 |
| Admin action | `POST /lab/v1/admin/actions/{action}` | `archive`, `export`; AUTHZ-005–006 |
| State transition | `POST /lab/v1/resources/{resource_id}/actions/{action}` | `request_return`, `refund`, `approve_refund`, `assign`, `close`; AUTHZ-013–015, 020 |
| Invoice | `/lab/v1/invoices`, `/lab/v1/invoices/{invoice_id}` và `submit/approve/pay/void` | Draft → submitted → approved → paid; AUTHZ-INV-01–03 |
| Payout | `/lab/v1/payouts`, `/lab/v1/payouts/{payout_id}` và `approve/release` | Pending → approved → released; AUTHZ-PAY-01–02 |
| Ticket mở rộng | `POST /lab/v1/tickets/{resource_id}/escalate` và `/resolve` | Assigned → escalated → resolved; AUTHZ-TCK-01 |
| Review | `POST/GET /lab/v1/orders/{resource_id}/reviews`, `PATCH/DELETE /lab/v1/reviews/{review_id}` | Thuộc tính Verified/Featured; AUTHZ-REV-01–02 |
| History | `GET /lab/v1/invoices/{invoice_id}/history`, `/lab/v1/payouts/{payout_id}/history`, `/lab/v1/resources/{resource_id}/history` | Đọc event history đã redacted; operation hợp lệ để tính endpoint coverage |

Các route extension được đăng ký qua `app/__init__.py`, không xuất hiện trong OpenAPI gốc do `include_in_schema=False`. RSO hiện khai báo 30 action ở lớp Cyber Range; catalog này bao gồm cả query variant và thao tác nghiệp vụ trên extension, nên mẫu số operation nên được định nghĩa theo action ID trong RSO. Không lấy OpenAPI gốc làm mẫu số duy nhất.

### 9.3 Mapping case và workflow

Ground truth dùng field `operation_id` (không phải `op_id`), `scenario`, `severity`, `verification_status`; `split` là `development` hoặc `held-out`. Các cột `setup_steps`, `request_headers`, `request_body` và `evidence_required` chứa JSON được serialize trong cell CSV; loader parse thành cấu trúc khi seed. Nhóm 28 planted case gồm BOLA 6, BFLA 7, BOPLA 7, TENANT 4, WORKFLOW 4; có 8 benign case để tính false positive.

Các workflow khai báo bằng tên bước nghiệp vụ (`read_order`, `request_return`, `create_ticket`, …), trong khi RSO hiện chưa có các action ID tương ứng và một số bước là thao tác fixture/seed chứ không có route tạo riêng. Khi đo workflow coverage, log cần lưu `workflow_id`, `step_idx`, `action`/`operation_id`, `sequence_id`, `object_id`, actor, valid flag, state trước/sau; kiểm tra đúng thứ tự, precondition, postcondition và cùng object. Không thể suy ra workflow coverage chỉ bằng tìm một chuỗi `op_id` trong log như ví dụ script ban đầu.

### 9.4 Các điểm cần xử lý trước khi báo cáo KPI chính thức

| Phát hiện khi đọc code và artifact | Tác động | Cách ghi nhận/điều chỉnh trong lần cập nhật kế tiếp |
|---|---|---|
| Ví dụ schema/mẫu số đầu tài liệu không khớp RSO/CSV thật | Script theo ví dụ cũ không đọc được key hiện tại và có thể báo sai coverage | Dùng RSO, workflows, objects và planted CSV trong `cyber-range/`; cập nhật validator/script theo field thật |
| Actor supplier và fixture tài chính/review trước đây chỉ có trong app code | Không thể phát hành token/replay nhất quán từ artifact | Đã đồng bộ 2 supplier actor, 3 invoice, 2 payout và 1 review fixture vào RSO/`objects.json`; loader nạp chúng theo seed version 6 |
| Ticket extension cần ticket khác tenant ở trạng thái escalated; workflow trước đó thiếu mapping route/actor/object | Case AUTHZ-TCK-01 và sequence coverage không replay được từ seed | Đã thêm `ticket-b-001` ở trạng thái escalated và gắn operation/actor/object/precondition/postcondition vào workflow |
| API catch-all được đăng ký trước các route extension | Request invoice/payout/review/history bị dispatcher trả 404 | Đã chuyển catch-all dispatcher xuống cuối danh sách route trong `app/__init__.py`; smoke test xác nhận route extension hoạt động |
| `reset_database()` reset mọi collection trong `SEED_DATA`, bao gồm collection app ngoài `lab_*`; trong khi `seed_database()` chỉ seed `lab_*` theo phiên bản | Reset có thể làm rỗng dữ liệu mock API chính; phép đo giữa run phụ thuộc hành vi reset | Chốt quy trình reset riêng cho lab, ghi lại hash snapshot trước/sau; chưa coi reset là idempotent cho toàn app |
| `verified_by` và `verified_at` của cả 28 planted case đang rỗng; status là `pending-human-review` | Chưa thỏa điều kiện ground truth đã verify độc lập | Ghi coverage riêng cho case được probe và case đã xác minh; không mô tả planted case là đã human-verified |
| Audit event có request/response evidence ở app, nhưng coverage schema cũ chỉ có `raw_hash` | Provenance KPI không thể tính thống nhất từ log app nếu extractor chưa định nghĩa | Định nghĩa extraction/export của audit event, hash canonical request/response và liên kết `run_id`, `case_id`, `sequence_id`; không suy `raw_hash` từ status/response |

Do đó KPI trong mục 4 vẫn là mục tiêu thiết kế, chưa phải kết quả được xác nhận. Báo cáo đầu tiên cần nêu rõ denominator thực tế, các case chưa replay được, trạng thái verify và phiên bản flag/seed; chỉ so KPI sau khi các vấn đề khả năng thực thi và mapping đã được chốt trước run đánh giá.
