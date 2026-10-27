# How To Remove the Distrusted eMudhra Root CAs from CMK Add-ons (CVE-2026-111943)

## Introduction

On 2026-10-20, it was disclosed that the private keys of eight eMudhra intermediate
certificate authorities had been compromised (CVE-2026-111943). The intermediates chain
to four root CAs. Any client that trusts one of those roots will accept a certificate an
attacker issues with the stolen keys.

| Distrusted root CA | SHA-256 fingerprint |
| --- | --- |
| emSign ECC Root CA - G3 | `86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B` |
| AAA Certificate Services | `D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4` |
| emSign Root TLS CA - G3 | `7DD78D5F4F13459A83DFF9ABBBA62EDBAF6F2D102BF257FD712F4D9F2746ED8D` |
| emSign Root CS CA - G3 | `F2EDAAFF3D9B701FB4D14C9F285F8C0BAD90FC3BCC1FA07D47F4718EDABA34A5` |

Several CMK add-ons run upstream container images whose CA bundles include **emSign ECC
Root CA - G3** and **AAA Certificate Services**:

| Add-on | Where | Does it use the public trust store? |
| --- | --- | --- |
| CoreDNS | Deployment `kube-system/coredns` | No. Forwards over plain DNS and reaches the API server with the cluster's own CA. Only a `tls://` forward to a public resolver would use it. |
| Konnectivity agent | Deployment `kube-system/konnectivity-agent` | No. Validates its one TLS connection against the cluster CA passed in `--ca-cert`. |
| kube-state-metrics | Deployment `kube-system/kube-state-metrics` | No, in the default configuration. Only `kubeconfig.enabled` pointed at an external API server over a publicly trusted connection would use it. |
| cert-manager (`controller`) | Deployment `cert-manager/cert-manager` | **Possibly yes.** If any `Issuer`/`ClusterIssuer` is an ACME issuer pointed at a public CA such as Let's Encrypt, the controller validates that CA against the public trust store. Internal issuers (for example Vault-backed, which is how CMK's own install is configured) are unaffected. |
| cert-manager (`webhook`, `cainjector`) | Deployments `cert-manager/cert-manager-webhook`, `cert-manager/cert-manager-cainjector` | No. They talk only to the Kubernetes API server. Covered here so the images pass trust-store scans. |

For most clusters this is hygiene: it makes the images pass trust-store scans and removes
a latent dependency on the current configuration, and changes nothing about how the
add-ons run. **cert-manager with a public ACME issuer is the one case where it closes a
real exposure**, so prioritise that cluster if you have one.

This directory covers the **add-on container images**. The host operating system of your
nodes is a separate trust store, remediated by the
[`emudhra_ca` role and `crusoe-distrust-emudhra-ca` chart](../../crusoe-cs-ansible/) in
this repository; the two are independent and both are needed for a fully clean cluster.

The script `cmk-emudhra-ca-fix.sh` applies the fix to every applicable add-on in one go,
**without changing any add-on's version, configuration, or Helm values, and without a
build toolchain or a container registry.**

## Does this apply to your cluster?

The script works it out for itself, and you can see its verdict without changing
anything:

```bash
./cmk-emudhra-ca-fix.sh --list
```

For each add-on it looks for the Deployment:

- **Deployment present** — the add-on is yours to change and the script patches it.
- **Not installed** — skipped. cert-manager in particular is optional and absent from
  most clusters.
- **Fix already present** — reported and skipped, so the script is safe to re-run.

If an add-on was installed under a non-default Helm release name, its Deployment name
will not match and the script will report it as not installed. Use `--print-patch` to get
the patch and apply it by hand to the Deployment you do have. The script does look up a
Deployment in a different namespace by name, so a cert-manager installed outside the
`cert-manager` namespace is found automatically.

## How the fix works

- A strategic-merge `kubectl patch` on each Deployment adds one init container, one
  in-memory volume, and one volume mount. Nothing else in the Deployment, its ConfigMaps,
  or its Helm release is touched, so customised configuration survives.
- The init container, `filter-ca-certs`, runs on `alpine:3.22` pinned by digest. Crusoe
  verified that image's CA bundle: Alpine 3.22.7, 118 certificates, none of the four
  distrusted roots. The init container copies that bundle into the in-memory volume and
  exits. It installs no packages, needs no network at pod start, runs as an unprivileged
  uid with a read-only root filesystem and no capabilities, and refuses to start the pod
  if the bundle it is about to install is missing or implausibly small.
- The add-on container mounts the volume read-only over `/etc/ssl/certs`, so the process
  sees the clean bundle instead of the one baked into its image.
- For the konnectivity agent the patch also sets the Deployment's rolling-update strategy
  to `maxUnavailable: 1`. That agent as installed carries the Kubernetes default strategy,
  which at three replicas allows zero pods to be unavailable; combined with its hard
  anti-affinity (three replicas on three distinct nodes), no rollout can complete on a
  cluster with exactly three workers. The setting lets one old pod be removed first, and
  is harmless on larger clusters.
- Each add-on rolls one pod at a time, and the script waits for each rollout before
  starting the next. CoreDNS keeps serving throughout, and the API server keeps at least
  two konnectivity tunnels. A long-running `kubectl exec` or `port-forward` session that
  happens to ride the konnectivity agent being replaced is disconnected once and must be
  reopened. kube-state-metrics is a single replica, so Prometheus may miss a scrape.
  cert-manager's webhook briefly shifts to a new pod, so a cert-manager API request made
  during that second may need a retry.
- The patch is keyed on container and volume names. Helm's three-way merge and
  `kubectl apply` both preserve live fields that the add-on's own manifests do not set,
  and none of these charts sets `initContainers`, so the fix carries over routine add-on
  and CMK upgrades. If CMK later ships the same init container built in, the two merge
  into one. Confirm after an upgrade with `--list`.

## Prerequisites

- `kubectl` with access to the cluster and permission to get and patch Deployments in
  `kube-system` and, if cert-manager is installed, its namespace (cluster-admin, which
  CMK grants to the cluster creator).
- `bash` (the stock macOS `/bin/bash` 3.2 is fine).

**Private clusters.** The init container image is pulled from Docker Hub. If your nodes
cannot reach Docker Hub, copy the image into a registry they can reach and pass it with
`--init-image`. `skopeo copy --all` preserves the digest, so the pin stays intact:

```bash
skopeo copy --all \
  docker://alpine:3.22@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f \
  docker://<your-registry>/alpine:3.22
./cmk-emudhra-ca-fix.sh --init-image <your-registry>/alpine:3.22@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f
```

## Instructions

### Step 1: Get and review the script

Clone this repository or download `cmk-emudhra-ca-fix.sh` from this directory, and make
it executable. To see exactly what will be patched, print a patch:

```bash
git clone https://github.com/crusoecloud/crusoe-cs.git
cd crusoe-cs/crusoe-scripts/emudhra
chmod +x cmk-emudhra-ca-fix.sh
./cmk-emudhra-ca-fix.sh --print-patch coredns
./cmk-emudhra-ca-fix.sh --print-patch cert-manager-controller
```

### Step 2: See what is installed, then dry run

```bash
./cmk-emudhra-ca-fix.sh --list
./cmk-emudhra-ca-fix.sh --dry-run
```

The dry run has the API server validate each patch without applying it. Expect one line
per add-on:

```
Cluster: Kubernetes v1.34.5
Mode:    dry run, nothing will change

✓ coredns: patch accepted by the API server (dry run); would roll 3 pods in kube-system
✓ konnectivity-agent: patch accepted by the API server (dry run); would roll 3 pods in kube-system
✓ kube-state-metrics: patch accepted by the API server (dry run); would roll 1 pods in kube-system
– cert-manager-controller: not installed (no Deployment cert-manager/cert-manager)
– cert-manager-webhook: not installed (no Deployment cert-manager/cert-manager-webhook)
– cert-manager-cainjector: not installed (no Deployment cert-manager/cert-manager-cainjector)

Summary: 0 changed, 3 skipped, 0 failed
```

### Step 3: Apply

```bash
./cmk-emudhra-ca-fix.sh
```

The script patches each applicable add-on in turn, waits for its rolling restart,
verifies every new pod's init container reported success and that the mount is live, and
prints the result before moving on:

```
coredns: applying
   patched; waiting for the rolling restart (up to 5m)
✓ coredns: fixed: 3 pods rolled, clean bundle of 118 certificates mounted over /etc/ssl/certs
...
Summary: 3 changed, 3 skipped, 0 failed
```

During a roll a new pod may briefly show `Pending` with a `FailedScheduling` event
mentioning anti-affinity. That is expected: the new pod is waiting for an old one on the
same node to be removed, which happens within a minute.

A failure on one add-on is reported with `✗` and a pointer to the pod log to inspect; the
script continues with the next add-on and exits non-zero at the end. The old pods keep
serving while a new pod is stuck, so a failed roll does not cause an outage. Use
`--only <add-on>` to retry one add-on after fixing the cause; `--only cert-manager`
selects all three cert-manager components.

### Step 4: Verify (optional)

The script already checks each pod's init log and the mount. To look yourself:

```bash
kubectl -n kube-system logs deployment/coredns -c filter-ca-certs
./cmk-emudhra-ca-fix.sh --list
```

Expect `ca-certs: ok: installed 118 certificates from the pinned alpine 3.22 bundle`.

If your cert-manager uses a public ACME issuer, confirm issuance still works after the
change by watching an existing `Certificate` renew, or by issuing a throwaway one against
your ACME staging endpoint.

## Rolling back

```bash
./cmk-emudhra-ca-fix.sh --rollback
```

Removes the init container, volume, and mount from each patched add-on with a rolling
restart, and reports each result. The konnectivity agent's `maxUnavailable: 1` is
deliberately kept: the rollback is itself a rolling update and would deadlock without it
on a three-worker cluster, and keeping it protects future rollouts of that Deployment the
same way. To restore that Deployment byte for byte as CMK installed it, run this only
after the rollback has finished (changing the strategy alone restarts no pod):

```bash
kubectl -n kube-system patch deployment konnectivity-agent --type strategic \
  -p '{"spec":{"strategy":{"rollingUpdate":{"maxUnavailable":"25%"}}}}'
```

## Later upgrades and removing the fix

- The fix survives routine add-on and CMK upgrades, because none of these charts sets
  `initContainers` and both Helm and `kubectl apply` preserve live fields their manifests
  do not set. Run `--list` after an upgrade to confirm.
- Once an add-on moves to an image that no longer ships these roots, remove the fix for
  it with `--rollback --only <add-on>`.

## Additional Resources

- [eMudhra intermediate CA compromise advisory](https://emudhra.we-have-a-problem.com/)
- [Red Hat RHSB-2026-012](https://access.redhat.com/security/vulnerabilities/RHSB-2026-012)
- [CoreDNS releases](https://github.com/coredns/coredns/releases)
- [apiserver-network-proxy (konnectivity) releases](https://github.com/kubernetes-sigs/apiserver-network-proxy/releases)
- [kube-state-metrics releases](https://github.com/kubernetes/kube-state-metrics/releases)
- [cert-manager releases](https://github.com/cert-manager/cert-manager/releases)
