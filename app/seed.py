"""Deterministic application fixtures and Cyber Range artifact loader."""
import csv
import json
from pathlib import Path

LAB_SEED_VERSION = 4
SEED_DATA = {
    "customers": [
        {"ID": "11111111-1111-4111-8111-111111111111", "Name": "Linh Nguyen", "Email": "linh@example.test", "PhoneNumber": "0901234567", "BirthDate": "1998-04-12", "Password": "demo123", "Roles": ["Customer"], "TenantID": "tenant-a", "Active": True},
        {"ID": "22222222-2222-4222-8222-222222222222", "Name": "Minh Tran", "Email": "minh@example.test", "PhoneNumber": "0912345678", "BirthDate": "1995-09-03", "Password": "demo123", "Roles": ["Customer"], "TenantID": "tenant-b", "Active": True},
    ],
    "suppliers": [
        {"ID": "33333333-3333-4333-8333-333333333333", "Name": "Acme Supply", "Email": "supplier@example.test", "Password": "demo123", "PhoneNumber": "0281234567", "Roles": ["Supplier"], "TenantID": "tenant-a", "Active": True},
    ],
    "supplier_companies": [
        {"ID": "44444444-4444-4444-8444-444444444444", "SupplierID": "33333333-3333-4333-8333-333333333333", "Name": "Acme Supply Co.", "Email": "contact@acme.example.test", "IsExemptedFromMarketplaceFee": 0, "CertificateOfIncorporationPDFBase64": ""},
    ],
    "products": [
        {"ID": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "SupplierID": "33333333-3333-4333-8333-333333333333", "Name": "Wireless Mouse", "Price": 25.5, "PNGPhotoFileURI": "", "PNGPhotoFileBase64": "", "Stock": 25},
        {"ID": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "SupplierID": "33333333-3333-4333-8333-333333333333", "Name": "Mechanical Keyboard", "Price": 79.99, "PNGPhotoFileURI": "", "PNGPhotoFileBase64": "", "Stock": 12},
        {"ID": "cccccccc-cccc-4ccc-8ccc-cccccccccccc", "SupplierID": "33333333-3333-4333-8333-333333333333", "Name": "USB-C Hub", "Price": 39.0, "PNGPhotoFileURI": "", "PNGPhotoFileBase64": "", "Stock": 18},
    ],
    "product_discounts": [
        {"ID": "dddddddd-dddd-4ddd-8ddd-dddddddddddd", "ProductID": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "Percentage": 10, "StartsAt": "2026-01-01", "EndsAt": "2026-12-31"},
        {"ID": "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", "ProductID": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "Percentage": 5, "StartsAt": "2026-01-01", "EndsAt": "2026-12-31"},
    ],
    "customer_orders": [
        {"ID": "55555555-5555-4555-8555-555555555555", "CustomerID": "11111111-1111-4111-8111-111111111111", "Date": "2026-10-01", "Status": "Processing"},
        {"ID": "66666666-6666-4666-8666-666666666666", "CustomerID": "22222222-2222-4222-8222-222222222222", "Date": "2026-10-04", "Status": "Delivered"},
    ],
    "customer_order_items": [
        {"ID": "77777777-7777-4777-8777-777777777777", "OrderID": "55555555-5555-4555-8555-555555555555", "ProductID": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "Quantity": 2, "NetSum": 45.9},
        {"ID": "88888888-8888-4888-8888-888888888888", "OrderID": "55555555-5555-4555-8555-555555555555", "ProductID": "cccccccc-cccc-4ccc-8ccc-cccccccccccc", "Quantity": 1, "NetSum": 39.0},
        {"ID": "99999999-9999-4999-8999-999999999999", "OrderID": "66666666-6666-4666-8666-666666666666", "ProductID": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "Quantity": 1, "NetSum": 75.99},
    ],
    "customer_payment_options": [
        {"ID": "12121212-1212-4212-8212-121212121212", "CustomerID": "11111111-1111-4111-8111-111111111111", "Type": "CreditCard", "Provider": "Visa", "AccountNumber": "****4242", "CVV": "***"},
    ],
    "customer_billing_addresses": [
        {"ID": "13131313-1313-4313-8313-131313131313", "CustomerID": "11111111-1111-4111-8111-111111111111", "City": "Ho Chi Minh City", "Country": "Vietnam", "Street": "12 Nguyen Hue", "PostalCode": "700000"},
        {"ID": "14141414-1414-4414-8414-141414141414", "CustomerID": "22222222-2222-4222-8222-222222222222", "City": "Hanoi", "Country": "Vietnam", "Street": "25 Hang Bai", "PostalCode": "100000"},
    ],
    "supplier_company_yearly_reports": [
        {"ID": 2025, "SupplierCompanyID": "44444444-4444-4444-8444-444444444444", "Year": 2025, "Revenue": 125000.0, "Currency": "USD"},
    ],
    "supplier_quarterly_reports": [
        {"ID": 1, "SupplierID": "33333333-3333-4333-8333-333333333333", "Year": 2026, "Quarter": 1, "Revenue": 32500.0, "Currency": "USD"},
        {"ID": 2, "SupplierID": "33333333-3333-4333-8333-333333333333", "Year": 2026, "Quarter": 2, "Revenue": 41800.0, "Currency": "USD"},
    ],
    "lab_sessions": [],
}


# Cyber Range artifacts are canonical for lab actors, objects, workflows and
# ground truth. YAML files use the JSON-compatible YAML 1.2 subset so the
# runtime needs only Python's standard library.
_RANGE = Path(__file__).resolve().parents[1] / "cyber-range"
def _load_json_yaml(relative_path):
    with (_RANGE / relative_path).open(encoding="utf-8") as artifact:
        return json.load(artifact)

_rso = _load_json_yaml("model/rso.yaml")
_workflows = _load_json_yaml("workflows/workflows.yaml")
_objects = _load_json_yaml("seed/objects.json")
SEED_DATA["lab_tenants"] = _rso["tenants"]
SEED_DATA["lab_actors"] = _rso["actors"]
SEED_DATA["lab_resources"] = _objects["objects"]
SEED_DATA["lab_workflows"] = _workflows["workflows"]
SEED_DATA["lab_ground_truth"] = []
SEED_DATA["lab_benign_cases"] = []
with (_RANGE / "ground_truth/planted_cases.csv").open(newline="", encoding="utf-8") as artifact:
    for row in csv.DictReader(artifact):
        benign = row["is_benign"].lower() == "true"
        case = {
            "ID": row["case_id"] if benign else f"GT-{row['case_id'].split('-')[-1]}",
            "CaseID": row["case_id"], "App": row["app"], "Family": row["family"],
            "Scenario": row["scenario"], "OperationID": row["operation_id"],
            "Method": row["method"], "Path": row["path"],
            "Attacker": row["attacker"] or None, "Victim": row["victim"] or None,
            "ObjectID": row["object_id"] or None, "OracleType": row["oracle_type"],
            "ExpectedSafe": row["expected_safe"], "ObservedVulnerable": row["observed_vulnerable"],
            "Flag": row["flag"], "IsBenign": benign, "CWE": row["cwe"],
            "OWASP": row["owasp"], "Severity": row["severity"], "Split": row["split"],
            "EvidenceRequired": json.loads(row["evidence_required"]),
            "VerificationStatus": row["verification_status"],
            "VerifiedBy": row["verified_by"] or None, "VerifiedAt": row["verified_at"] or None,
            "Planted": not benign,
        }
        SEED_DATA["lab_benign_cases" if benign else "lab_ground_truth"].append(case)


def seed_database(database):
    """Insert app fixtures once and migrate lab fixtures by explicit seed version."""
    meta = database["lab_meta"]
    current = meta.find_one({"_id": "seed-version"}) or {}
    if current.get("Version", 0) < LAB_SEED_VERSION:
        # Only synthetic lab collections are reset on a fixture schema migration.
        for collection_name in SEED_DATA:
            if collection_name.startswith("lab_"):
                database[collection_name].delete_many({})
        for collection_name, documents in SEED_DATA.items():
            if collection_name.startswith("lab_") and documents:
                database[collection_name].insert_many([dict(document) for document in documents])
        meta.update_one({"_id": "seed-version"}, {"$set": {"Version": LAB_SEED_VERSION}}, upsert=True)
    for collection_name, documents in SEED_DATA.items():
        if collection_name.startswith("lab_"):
            continue
        collection = database[collection_name]
        for document in documents:
            collection.update_one({"ID": document["ID"]}, {"$setOnInsert": document}, upsert=True)


def reset_database(database):
    """Reset only declared lab collections to their deterministic seed state.

    Audit events are intentionally preserved. Call only from an explicitly
    enabled, authenticated local-lab reset route or a trusted admin command.
    """
    for collection_name, documents in SEED_DATA.items():
        collection = database[collection_name]
        collection.delete_many({})
        if documents:
            collection.insert_many([dict(document) for document in documents])
    return {"collections_reset": len(SEED_DATA), "seed_records": sum(map(len, SEED_DATA.values()))}
