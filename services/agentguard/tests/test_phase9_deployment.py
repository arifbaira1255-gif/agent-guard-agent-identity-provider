"""Phase 9 -- deployment / container configuration conformance.

Static assertions over the deployment assets. These do NOT prove the manifests apply to a live
cluster (no API server is available in this environment) -- they prove the security-relevant
properties are present and that the YAML is well-formed. Live-cluster validation is reported as
BLOCKED in the Phase 9 report.
"""
from __future__ import annotations

import os
import re
import unittest

import yaml

ROOT = os.path.join(os.path.dirname(__file__), "..")
K8S = os.path.join(ROOT, "deploy", "kubernetes")


def _load_all(path):
    with open(path) as fh:
        return [d for d in yaml.safe_load_all(fh) if d]


def _all_docs():
    docs = []
    for name in sorted(os.listdir(K8S)):
        if name.endswith((".yaml", ".yml")):
            for d in _load_all(os.path.join(K8S, name)):
                docs.append((name, d))
    return docs


class ManifestConformanceTests(unittest.TestCase):
    def test_all_manifests_parse(self):
        docs = _all_docs()
        self.assertGreater(len(docs), 10, "expected the full topology to be present")

    def test_namespace_enforces_restricted_psa(self):
        ns = [d for _, d in _all_docs() if d.get("kind") == "Namespace"][0]
        labels = ns["metadata"]["labels"]
        self.assertEqual(labels.get("pod-security.kubernetes.io/enforce"), "restricted")

    def test_deployment_runs_non_root_and_drops_caps(self):
        dep = [d for _, d in _all_docs() if d.get("kind") == "Deployment"][0]
        pod_sc = dep["spec"]["template"]["spec"]["securityContext"]
        self.assertTrue(pod_sc.get("runAsNonRoot"))
        self.assertNotEqual(pod_sc.get("runAsUser"), 0)
        ctr = dep["spec"]["template"]["spec"]["containers"][0]
        self.assertFalse(ctr["securityContext"].get("allowPrivilegeEscalation", True))
        self.assertIn("ALL", ctr["securityContext"]["capabilities"]["drop"])

    def test_deployment_has_all_three_probes(self):
        dep = [d for _, d in _all_docs() if d.get("kind") == "Deployment"][0]
        ctr = dep["spec"]["template"]["spec"]["containers"][0]
        for probe in ("livenessProbe", "readinessProbe", "startupProbe"):
            self.assertIn(probe, ctr, f"{probe} is required")
        # Liveness must be the process-only endpoint, never a dependency check.
        self.assertEqual(ctr["livenessProbe"]["httpGet"]["path"], "/livez")
        self.assertEqual(ctr["readinessProbe"]["httpGet"]["path"], "/readyz")

    def test_deployment_has_resources_and_graceful_shutdown(self):
        dep = [d for _, d in _all_docs() if d.get("kind") == "Deployment"][0]
        ctr = dep["spec"]["template"]["spec"]["containers"][0]
        self.assertIn("requests", ctr["resources"])
        self.assertIn("limits", ctr["resources"])
        self.assertGreaterEqual(dep["spec"]["template"]["spec"]["terminationGracePeriodSeconds"], 20)
        self.assertIn("preStop", ctr["lifecycle"])

    def test_rolling_update_never_drops_below_desired(self):
        dep = [d for _, d in _all_docs() if d.get("kind") == "Deployment"][0]
        self.assertEqual(dep["spec"]["strategy"]["rollingUpdate"]["maxUnavailable"], 0)

    def test_serviceaccount_does_not_automount_token(self):
        sas = [d for _, d in _all_docs() if d.get("kind") == "ServiceAccount"]
        self.assertTrue(sas)
        for sa in sas:
            self.assertFalse(sa.get("automountServiceAccountToken", True),
                             f"{sa['metadata']['name']} must not automount a token")

    def test_default_deny_network_policy_present(self):
        nps = [d for _, d in _all_docs() if d.get("kind") == "NetworkPolicy"]
        names = {n["metadata"]["name"] for n in nps}
        self.assertIn("default-deny-all", names)
        deny = next(n for n in nps if n["metadata"]["name"] == "default-deny-all")
        self.assertEqual(set(deny["spec"]["policyTypes"]), {"Ingress", "Egress"})

    def test_no_plaintext_secret_in_configmap(self):
        cms = [d for _, d in _all_docs() if d.get("kind") == "ConfigMap"]
        for cm in cms:
            for k, v in (cm.get("data") or {}).items():
                self.assertNotRegex(k, r"(?i)password|secret|master_key|private",
                                    f"ConfigMap {cm['metadata']['name']} must not hold {k}")
                self.assertNotRegex(str(v), r"-----BEGIN", "no key material in a ConfigMap")

    def test_secret_example_is_marked_as_example(self):
        path = os.path.join(K8S, "11-secrets.example.yaml")
        self.assertTrue(os.path.exists(path))
        with open(path) as fh:
            head = fh.read(400)
        self.assertRegex(head, r"(?i)example only|do not commit")

    def test_migration_job_is_separate_from_deployment(self):
        jobs = [d for _, d in _all_docs() if d.get("kind") == "Job"]
        self.assertTrue(jobs, "migrations must run as a Job, not at app startup")
        dep = [d for _, d in _all_docs() if d.get("kind") == "Deployment"][0]
        env = dep["spec"]["template"]["spec"]["containers"][0].get("envFrom", [])
        self.assertTrue(any("configMapRef" in e for e in env))

    def test_pdb_and_hpa_present(self):
        kinds = {d.get("kind") for _, d in _all_docs()}
        self.assertIn("PodDisruptionBudget", kinds)
        self.assertIn("HorizontalPodAutoscaler", kinds)

    def test_ingress_terminates_tls(self):
        ing = [d for _, d in _all_docs() if d.get("kind") == "Ingress"][0]
        self.assertTrue(ing["spec"].get("tls"), "ingress must terminate TLS")
        self.assertEqual(ing["metadata"]["annotations"].get("nginx.ingress.kubernetes.io/ssl-redirect"),
                         "true")


class DockerfileConformanceTests(unittest.TestCase):
    def _dockerfile(self):
        with open(os.path.join(ROOT, "Dockerfile")) as fh:
            return fh.read()

    def test_multistage_build(self):
        df = self._dockerfile()
        self.assertGreaterEqual(len(re.findall(r"(?m)^FROM ", df)), 2, "must be multi-stage")

    def test_runs_as_non_root(self):
        df = self._dockerfile()
        self.assertRegex(df, r"(?m)^USER 10001:10001")
        self.assertNotRegex(df, r"(?m)^USER root")

    def test_no_credentials_baked_in(self):
        df = self._dockerfile()
        self.assertNotRegex(df, r"(?i)(password|secret|api[_-]?key)\s*=\s*['\"][^'\"]{8,}")

    def test_healthcheck_uses_liveness_endpoint(self):
        df = self._dockerfile()
        self.assertIn("/livez", df)

    def test_dockerignore_excludes_secrets_and_tests(self):
        with open(os.path.join(ROOT, ".dockerignore")) as fh:
            di = fh.read()
        for pat in (".env", "*.pem", "*.key", "tests"):
            self.assertIn(pat, di)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
