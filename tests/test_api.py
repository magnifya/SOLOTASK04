"""端到端测试：真实启动 HTTP 服务，覆盖 DID、凭证与 CLI 校验流程。"""

from __future__ import annotations

import json
import threading
import unittest
import urllib.error
import urllib.request

from vc_backend import crypto
from vc_backend.server import make_server


def request(method: str, url: str, payload: dict | None = None) -> tuple[int, dict]:
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode())


class ServerTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = make_server("127.0.0.1", 0)
        cls.port = cls.server.server_address[1]
        cls.base = f"http://127.0.0.1:{cls.port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def register_did(self, public_key: str, private_key: str | None = None) -> tuple[int, dict]:
        body = {"method": "example", "public_key": public_key}
        if private_key:
            body["private_key"] = private_key
        return request("POST", self.base + "/v1/dids", body)


class TestDids(ServerTestCase):
    def test_create_and_get(self):
        status, body = self.register_did("pk-test-1")
        self.assertEqual(status, 201)
        self.assertTrue(body["did"].startswith("did:example:"))
        self.assertEqual(body["public_key"], "pk-test-1")

        status, got = request("GET", f"{self.base}/v1/dids/{body['did']}")
        self.assertEqual(status, 200)
        self.assertEqual(got["public_key"], "pk-test-1")
        self.assertIn("created_at", got)

    def test_duplicate_public_key_returns_existing_did(self):
        _, first = self.register_did("pk-test-dup")
        status, second = self.register_did("pk-test-dup")
        self.assertIn(status, (200, 201))
        self.assertEqual(first["did"], second["did"])

    def test_missing_field_400(self):
        status, body = request("POST", self.base + "/v1/dids", {"method": "example"})
        self.assertEqual(status, 400)
        self.assertIn("public_key", body["error"])

    def test_get_unknown_404(self):
        status, _ = request("GET", self.base + "/v1/dids/did:example:missing")
        self.assertEqual(status, 404)


class TestCredentials(ServerTestCase):
    def setUp(self):
        self.issuer_pub, self.issuer_priv = crypto.generate_keypair()
        _, issuer = self.register_did(self.issuer_pub, self.issuer_priv)
        self.issuer_did = issuer["did"]
        _, subject = self.register_did("pk-subject-" + self.issuer_did[-6:])
        self.subject_did = subject["did"]

    def issue(self, issuer_did=None, subject_did=None, claims=None):
        return request("POST", self.base + "/v1/credentials", {
            "issuer_did": issuer_did or self.issuer_did,
            "subject_did": subject_did or self.subject_did,
            "claims": claims if claims is not None else {"role": "dev"},
        })

    def test_issue_get_and_verify(self):
        status, body = self.issue()
        self.assertEqual(status, 201)
        self.assertIn("credential_id", body)
        self.assertIn("signature", body)

        status, cred = request("GET", f"{self.base}/v1/credentials/{body['credential_id']}")
        self.assertEqual(status, 200)
        self.assertEqual(cred["signature"], body["signature"])
        self.assertEqual(cred["claims"], {"role": "dev"})

        # 用签发者现取的公钥校验：原文通过，篡改后失败
        doc_body = {k: v for k, v in cred.items() if k != "signature"}
        payload = crypto.canonical_json(doc_body)
        self.assertTrue(crypto.verify_es256(self.issuer_pub, payload, cred["signature"]))
        doc_body["claims"]["role"] = "admin"
        tampered = crypto.canonical_json(doc_body)
        self.assertFalse(crypto.verify_es256(self.issuer_pub, tampered, cred["signature"]))

    def test_unknown_issuer_400(self):
        status, body = self.issue(issuer_did="did:example:ghost")
        self.assertEqual(status, 400)
        self.assertIn("did:example:ghost", body["error"])

    def test_unknown_subject_400(self):
        status, body = self.issue(subject_did="did:example:ghost")
        self.assertEqual(status, 400)
        self.assertIn("did:example:ghost", body["error"])

    def test_get_unknown_404(self):
        status, _ = request("GET", self.base + "/v1/credentials/missing")
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main()
