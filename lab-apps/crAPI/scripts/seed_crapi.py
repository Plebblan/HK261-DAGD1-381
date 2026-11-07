#!/usr/bin/env python3
"""Create synthetic crAPI records for the in-scope seed scenarios."""

from __future__ import annotations

import argparse
import json
import ssl
import sys
import uuid
from datetime import datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen


SEED_FILE = (
    Path(__file__).resolve().parents[1]
    / "cyber-range"
    / "seeds"
    / "crapi_seed.json"
)
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
VIDEO_PLACEHOLDER = (
    b"\x00\x00\x00\x18ftypisom\x00\x00\x02\x00isomiso2"
    b"\x00\x00\x00\x08free\x00\x00\x00\x0cmdatseed"
)


class CrAPI:
    def __init__(self, base_url: str, timeout: float) -> None:
        parsed = urlsplit(base_url)
        if parsed.scheme not in {"http", "https"} or parsed.hostname not in LOCAL_HOSTS:
            raise ValueError("base URL must use HTTP(S) on localhost or a loopback address")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.ssl_context = ssl.create_default_context()
        if parsed.scheme == "https":
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE

    def request(
        self,
        method: str,
        path: str,
        *,
        token: str | None = None,
        body: dict | None = None,
        multipart: tuple[str, bytes] | None = None,
    ) -> tuple[int, object]:
        headers = {"Accept": "application/json"}
        raw_body = None
        if token:
            headers["Authorization"] = f"Bearer {token.removeprefix('Bearer ')}"
        if body is not None:
            headers["Content-Type"] = "application/json"
            raw_body = json.dumps(body).encode("utf-8")
        elif multipart is not None:
            filename, file_bytes = multipart
            boundary = f"----crapi-seed-{uuid.uuid4().hex}"
            headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
            raw_body = (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
                "Content-Type: video/mp4\r\n\r\n"
            ).encode("utf-8") + file_bytes + f"\r\n--{boundary}--\r\n".encode("ascii")

        request = Request(
            f"{self.base_url}/{path.lstrip('/')}",
            data=raw_body,
            headers=headers,
            method=method,
        )
        try:
            with urlopen(request, timeout=self.timeout, context=self.ssl_context) as response:
                status = response.status
                response_bytes = response.read()
        except HTTPError as error:
            status = error.code
            response_bytes = error.read()
        except URLError as error:
            raise RuntimeError(f"{method} {path} failed: {error.reason}") from error

        if not response_bytes:
            return status, None
        text = response_bytes.decode("utf-8", errors="replace")
        try:
            return status, json.loads(text)
        except json.JSONDecodeError:
            return status, text


def require_status(
    status: int, payload: object, expected: tuple[int, ...], operation: str
) -> object:
    if status not in expected:
        raise RuntimeError(f"{operation} returned HTTP {status}: {payload}")
    return payload


def save_seed(seed: dict) -> None:
    SEED_FILE.write_text(
        json.dumps(seed, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def ensure_user(api: CrAPI, actor: dict) -> str:
    signup = {
        "email": actor["email"],
        "name": actor["name"],
        "number": actor["number"],
        "password": actor["password"],
    }
    status, payload = api.request("POST", "/identity/api/auth/signup", body=signup)
    signup_succeeded = status in (200, 201)
    if not signup_succeeded:
        signup_failure = f"signup HTTP {status}: {payload}"

    status, payload = api.request(
        "POST",
        "/identity/api/auth/login",
        body={"email": actor["email"], "password": actor["password"]},
    )
    try:
        require_status(status, payload, (200,), f"login for {actor['key']}")
    except RuntimeError as error:
        if not signup_succeeded:
            raise RuntimeError(f"{signup_failure}; {error}") from error
        raise
    if not isinstance(payload, dict) or not isinstance(payload.get("token"), str):
        raise RuntimeError(f"login for {actor['key']} returned no token: {payload}")
    if not signup_succeeded:
        print(f"Reusing {actor['key']} account ({signup_failure}).")
    return payload["token"]


def ensure_vehicle(api: CrAPI, actor: dict, token: str) -> dict:
    status, payload = api.request("GET", "/identity/api/v2/vehicle/vehicles", token=token)
    require_status(status, payload, (200,), f"list vehicles for {actor['key']}")
    if not isinstance(payload, list):
        raise RuntimeError(f"vehicle list had an unexpected response: {payload}")
    candidates = [actor["vehicle"]["vin"], *actor.get("vehicle_vin_fallbacks", [])]
    vehicle = next(
        (
            item
            for item in payload
            if isinstance(item, dict) and item.get("vin") in candidates
        ),
        None,
    )
    if vehicle is not None:
        actor["vehicle"]["vin"] = vehicle["vin"]
    else:
        last_duplicate = None
        for vin in candidates:
            status, payload = api.request(
                "POST",
                "/identity/api/v2/vehicle/add_vehicle",
                token=token,
                body={"pincode": actor["vehicle"]["pincode"], "vin": vin},
            )
            if status in (200, 201):
                status, payload = api.request(
                    "GET", "/identity/api/v2/vehicle/vehicles", token=token
                )
                require_status(status, payload, (200,), f"verify vehicle for {actor['key']}")
                vehicle = next(
                    (
                        item
                        for item in payload
                        if isinstance(item, dict) and item.get("vin") == vin
                    ),
                    None,
                )
                if vehicle is None:
                    raise RuntimeError(f"vehicle {vin} was not found after creation")
                actor["vehicle"]["vin"] = vin
                break
            if status == 403 and "already added" in str(payload).lower():
                last_duplicate = vin
                continue
            require_status(status, payload, (200, 201), f"add vehicle {vin} for {actor['key']}")
        if vehicle is None:
            tried = ", ".join(candidates)
            raise RuntimeError(
                f"all configured VINs are already assigned ({tried}); "
                f"last duplicate was {last_duplicate}"
            )
    return {
        "id": vehicle.get("id"),
        "uuid": vehicle.get("uuid"),
        "vin": vehicle.get("vin"),
    }


def ensure_post(
    api: CrAPI, actor: dict, token: str, created: dict
) -> dict:
    post_id = created.get("community_post", {}).get("id")
    if post_id:
        status, payload = api.request(
            "GET",
            f"/community/api/v2/community/posts/{post_id}",
            token=token,
        )
        author = payload.get("author", {}) if isinstance(payload, dict) else {}
        if (
            status == 200
            and isinstance(payload, dict)
            and payload.get("title") == actor["community_post"]["title"]
            and author.get("email") == actor["email"]
        ):
            return {"id": post_id, "title": actor["community_post"]["title"]}

    status, payload = api.request(
        "POST",
        "/community/api/v2/community/posts",
        token=token,
        body=actor["community_post"],
    )
    require_status(status, payload, (200, 201), f"create post for {actor['key']}")
    if not isinstance(payload, dict) or payload.get("id") is None:
        raise RuntimeError(f"post creation returned no post ID: {payload}")
    return {"id": payload["id"], "title": actor["community_post"]["title"]}


def ensure_mechanic_report(
    api: CrAPI, actor: dict, token: str, created: dict, mechanic_api: str
) -> dict:
    report_id = created.get("mechanic_report", {}).get("id")
    if report_id is not None:
        status, report = api.request(
            "GET",
            f"/workshop/api/mechanic/mechanic_report?{urlencode({'report_id': report_id})}",
            token=token,
        )
        vehicle = report.get("vehicle", {}) if isinstance(report, dict) else {}
        report_owner = vehicle.get("owner", {}) if isinstance(vehicle, dict) else {}
        if status == 200 and report_owner.get("email") == actor["email"]:
            result = {"id": report_id}
            mechanic = report.get("mechanic", {})
            mechanic_code = mechanic.get("mechanic_code") if isinstance(mechanic, dict) else None
            if mechanic_code:
                result["mechanic_code"] = mechanic_code
            return result

    status, payload = api.request("GET", "/workshop/api/mechanic/", token=token)
    require_status(status, payload, (200,), "get mechanic list")
    mechanics = payload.get("mechanics") if isinstance(payload, dict) else None
    if not mechanics:
        raise RuntimeError(f"mechanic list was empty or malformed: {payload}")
    mechanic = mechanics[0]
    status, payload = api.request(
        "POST",
        "/workshop/api/merchant/contact_mechanic",
        token=token,
        body={
            "mechanic_api": mechanic_api,
            "mechanic_code": mechanic["mechanic_code"],
            "number_of_repeats": 1,
            "problem_details": actor["mechanic_request"]["problem_details"],
            "repeat_request_if_failed": False,
            "vin": actor["vehicle"]["vin"],
        },
    )
    require_status(status, payload, (200,), "create mechanic service report")
    response = payload.get("response_from_mechanic_api", {}) if isinstance(payload, dict) else {}
    if response.get("id") is None:
        raise RuntimeError(f"mechanic response contained no report ID: {payload}")
    return {"id": response["id"], "mechanic_code": mechanic["mechanic_code"]}


def ensure_video(
    api: CrAPI, actor: dict, token: str, created: dict
) -> dict:
    video_id = created.get("video", {}).get("id")
    if video_id is None:
        status, dashboard = api.request(
            "GET", "/identity/api/v2/user/dashboard", token=token
        )
        require_status(status, dashboard, (200,), f"get dashboard for {actor['key']}")
        if isinstance(dashboard, dict):
            video_id = dashboard.get("video_id")
    if video_id is not None:
        status, _ = api.request(
            "GET",
            f"/identity/api/v2/user/videos/{video_id}",
            token=token,
        )
        if status == 200:
            return {"id": video_id, "filename": actor["video"]["filename"]}

    status, payload = api.request(
        "POST",
        "/identity/api/v2/user/videos",
        token=token,
        multipart=(actor["video"]["filename"], VIDEO_PLACEHOLDER),
    )
    require_status(status, payload, (200, 201), f"upload video for {actor['key']}")
    if not isinstance(payload, dict) or payload.get("id") is None:
        raise RuntimeError(f"video upload returned no video ID: {payload}")
    return {"id": payload["id"], "filename": actor["video"]["filename"]}


def cheapest_product(api: CrAPI, token: str) -> dict:
    status, payload = api.request("GET", "/workshop/api/shop/products", token=token)
    require_status(status, payload, (200,), "list shop products")
    products = payload.get("products") if isinstance(payload, dict) else None
    if not products:
        raise RuntimeError(f"shop returned no products to order: {payload}")
    try:
        return min(products, key=lambda product: Decimal(str(product["price"])))
    except (InvalidOperation, KeyError, TypeError) as error:
        raise RuntimeError(f"shop returned products without valid prices: {payload}") from error


def current_order(
    api: CrAPI, token: str, order_id: object, expected: str, email: str
) -> dict | None:
    status, payload = api.request(
        "GET",
        f"/workshop/api/shop/orders/{order_id}",
        token=token,
    )
    order = (
        payload.get("order", payload.get("orders"))
        if isinstance(payload, dict)
        else None
    )
    user = order.get("user", {}) if isinstance(order, dict) else {}
    if (
        status == 200
        and isinstance(order, dict)
        and order.get("status") == expected
        and user.get("email") == email
    ):
        return order
    return None


def product_id_from_order(order: dict) -> object:
    product = order.get("product")
    if not isinstance(product, dict) or product.get("id") is None:
        raise RuntimeError(f"order response had no product ID: {order}")
    return product["id"]


def ensure_order(
    api: CrAPI,
    actor: dict,
    token: str,
    created: dict,
    product: dict,
    kind: str,
) -> dict:
    expected_status = "return pending" if kind == "return_pending" else "delivered"
    previous = created.get("orders", {}).get(kind, {})
    order_id = previous.get("id")
    existing_order = (
        current_order(api, token, order_id, expected_status, actor["email"])
        if order_id is not None
        else None
    )
    if existing_order is not None:
        return {
            "id": order_id,
            "status": expected_status,
            "product_id": product_id_from_order(existing_order),
        }

    status, payload = api.request(
        "POST",
        "/workshop/api/shop/orders",
        token=token,
        body={"product_id": product["id"], "quantity": 1},
    )
    require_status(status, payload, (200, 201), f"create {kind} order for {actor['key']}")
    if not isinstance(payload, dict) or payload.get("id") is None:
        raise RuntimeError(f"order creation returned no order ID: {payload}")
    order_id = payload["id"]

    if kind == "return_pending":
        status, payload = api.request(
            "POST",
            f"/workshop/api/shop/orders/return_order?{urlencode({'order_id': order_id})}",
            token=token,
        )
        require_status(status, payload, (200,), "request a normal order return")
    created_order = current_order(api, token, order_id, expected_status, actor["email"])
    if created_order is None:
        raise RuntimeError(
            f"created order {order_id} did not reach expected state {expected_status!r}"
        )
    return {
        "id": order_id,
        "status": expected_status,
        "product_id": product_id_from_order(created_order),
    }


def run(base_url: str, timeout: float) -> None:
    seed = json.loads(SEED_FILE.read_text(encoding="utf-8"))
    api = CrAPI(base_url, timeout)
    mechanic_api = seed["mechanic_api_url"]
    mechanic_url = urlsplit(mechanic_api)
    if mechanic_url.hostname not in LOCAL_HOSTS or mechanic_url.path != (
        "/workshop/api/mechanic/receive_report"
    ):
        raise ValueError("mechanic_api_url must target the local crAPI receive_report endpoint")

    created = seed.setdefault("created", {})
    tokens = {}
    for actor in seed["actors"]:
        actor_result = created.setdefault(actor["key"], {})
        tokens[actor["key"]] = ensure_user(api, actor)
        actor_result["email"] = actor["email"]

    owner = next(actor for actor in seed["actors"] if actor["key"] == "owner_a")
    owner_result = created["owner_a"]
    owner_token = tokens["owner_a"]

    owner_result["vehicle"] = ensure_vehicle(api, owner, owner_token)
    save_seed(seed)
    owner_result["community_post"] = ensure_post(
        api, owner, owner_token, owner_result
    )
    save_seed(seed)
    owner_result["mechanic_report"] = ensure_mechanic_report(
        api, owner, owner_token, owner_result, mechanic_api
    )
    save_seed(seed)
    owner_result["video"] = ensure_video(api, owner, owner_token, owner_result)
    save_seed(seed)

    product = cheapest_product(api, owner_token)
    owner_result["orders"] = owner_result.get("orders", {})
    owner_result["orders"]["delivered"] = ensure_order(
        api, owner, owner_token, owner_result, product, "delivered"
    )
    save_seed(seed)
    owner_result["orders"]["return_pending"] = ensure_order(
        api, owner, owner_token, owner_result, product, "return_pending"
    )
    seed["last_seeded_at"] = datetime.now().astimezone().isoformat()
    save_seed(seed)

    print(f"Seeded crAPI at {base_url}")
    print(f"Recorded created object IDs in {SEED_FILE}")
    for key, result in created.items():
        print(f"  {key}: {json.dumps(result, sort_keys=True)}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="https://localhost:8443")
    parser.add_argument("--timeout", type=float, default=20.0)
    args = parser.parse_args()
    try:
        run(args.base_url, args.timeout)
    except (KeyError, OSError, TypeError, ValueError, RuntimeError, json.JSONDecodeError) as error:
        print(f"Seed failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
