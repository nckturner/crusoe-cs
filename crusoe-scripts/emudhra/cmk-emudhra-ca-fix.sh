#!/usr/bin/env bash
# cmk-emudhra-ca-fix.sh
#
# Removes the root CAs distrusted after the eMudhra CA compromise
# (CVE-2026-111943) from the trust stores of the CMK add-ons that ship them,
# without changing any add-on's version, configuration, or Helm values:
#
#   coredns              Deployment kube-system/coredns
#   konnectivity-agent   Deployment kube-system/konnectivity-agent
#   kube-state-metrics   Deployment kube-system/kube-state-metrics
#   cert-manager         Deployments cert-manager/{cert-manager,-webhook,-cainjector}
#
# For each add-on it adds an init container that installs a clean, digest-pinned
# Alpine CA bundle into an in-memory volume, and mounts that volume read-only
# over /etc/ssl/certs in the add-on container. Each add-on is checked for
# applicability first, patched one at a time with a rolling restart, verified,
# and reported with a check mark or a cross. A failure on one add-on does not
# stop the others unless the cluster itself is unreachable. Add-ons that are not
# installed are skipped.
#
# Usage:
#   ./cmk-emudhra-ca-fix.sh                      apply to every applicable add-on
#   ./cmk-emudhra-ca-fix.sh --dry-run            server-side dry run, change nothing
#   ./cmk-emudhra-ca-fix.sh --rollback           remove the fix again
#   ./cmk-emudhra-ca-fix.sh --only cert-manager  limit to one add-on or group (repeatable)
#   ./cmk-emudhra-ca-fix.sh --list               show the add-ons and their state, change nothing
#   ./cmk-emudhra-ca-fix.sh --print-patch coredns   print a patch and exit
#
# Options:
#   --init-image REF   image for the init container (default below). On a
#                      private cluster, mirror the default with
#                      `skopeo copy --all` to a registry your nodes can reach
#                      and pass that reference; the @sha256 digest is preserved.
#   --timeout DUR      rollout wait per add-on (default 5m)
#   --kubeconfig PATH  passed through to kubectl
#   --context NAME     passed through to kubectl
#
# Requires kubectl with permission to get and patch Deployments in the
# namespaces above.
set -uo pipefail

INIT_IMAGE_DEFAULT="alpine:3.22@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f"
INIT_IMAGE="$INIT_IMAGE_DEFAULT"
TIMEOUT="5m"
MODE="apply"            # apply | dry-run | rollback | list | print-patch
ONLY=()
PRINT_ADDON=""
KUBECTL_ARGS=()

# name | group | namespace | deployment | container | pod selector | needs strategy fix
ADDONS=(
  "coredns|coredns|kube-system|coredns|coredns|k8s-app=coredns|no"
  "konnectivity-agent|konnectivity-agent|kube-system|konnectivity-agent|konnectivity-agent|k8s-app=konnectivity-agent|yes"
  "kube-state-metrics|kube-state-metrics|kube-system|kube-state-metrics|kube-state-metrics|app.kubernetes.io/name=kube-state-metrics|no"
  "cert-manager-controller|cert-manager|cert-manager|cert-manager|cert-manager-controller|app.kubernetes.io/component=controller|no"
  "cert-manager-webhook|cert-manager|cert-manager|cert-manager-webhook|cert-manager-webhook|app.kubernetes.io/component=webhook|no"
  "cert-manager-cainjector|cert-manager|cert-manager|cert-manager-cainjector|cert-manager-cainjector|app.kubernetes.io/component=cainjector|no"
)

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) MODE="dry-run" ;;
    --rollback) MODE="rollback" ;;
    --list) MODE="list" ;;
    --only) ONLY+=("$2"); shift ;;
    --print-patch) MODE="print-patch"; PRINT_ADDON="$2"; shift ;;
    --init-image) INIT_IMAGE="$2"; shift ;;
    --timeout) TIMEOUT="$2"; shift ;;
    --kubeconfig) KUBECTL_ARGS+=(--kubeconfig "$2"); shift ;;
    --context) KUBECTL_ARGS+=(--context "$2"); shift ;;
    -h|--help) sed -n '2,39p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

# reject an unknown --only name up front: otherwise it matches nothing and the
# run reports a clean summary without having touched anything
for o in ${ONLY[@]+"${ONLY[@]}"}; do
  known=no
  for entry in "${ADDONS[@]}"; do IFS='|' read -r name group _ <<<"$entry"
    [[ "$o" == "$name" || "$o" == "$group" ]] && known=yes
  done
  if [[ $known == no ]]; then
    echo "unknown add-on for --only: $o" >&2
    printf 'known: ' >&2; for entry in "${ADDONS[@]}"; do printf '%s ' "${entry%%|*}" >&2; done
    echo "cert-manager (all three cert-manager components)" >&2
    exit 2
  fi
done

OK="✓"; BAD="✗"; SKIP="–"
kc() { kubectl ${KUBECTL_ARGS[@]+"${KUBECTL_ARGS[@]}"} "$@"; }
k() { local ns="$1"; shift; kc -n "$ns" "$@"; }
note() { printf '   %s\n' "$*"; }
result() { printf '%s %s: %s\n' "$1" "$2" "$3"; }

# ---------- patch generation ----------
# The init container is identical for every add-on; only the target container
# name, and (for the konnectivity agent) the rollout strategy, differ.
patch_for() { # $1 container name, $2 needs-strategy (yes|no)
  local container="$1" strategy="$2"
  echo "spec:"
  if [[ "$strategy" == yes ]]; then
    cat <<'YAML'
  # The konnectivity agent pins 3 replicas to 3 nodes with hard anti-affinity
  # and ships with the default strategy (25%/25%), which allows ZERO pods to
  # be unavailable at 3 replicas: on a 3-worker cluster no rollout can ever
  # complete. maxUnavailable 1 lets one old pod be removed first.
  strategy:
    rollingUpdate:
      maxUnavailable: 1
YAML
  fi
  cat <<YAML
  template:
    spec:
      volumes:
        - name: filtered-ca-certs
          emptyDir:
            medium: Memory
            sizeLimit: 4Mi
      containers:
        - name: ${container}
          volumeMounts:
            - name: filtered-ca-certs
              mountPath: /etc/ssl/certs
              readOnly: true
      initContainers:
        # Installs the CA bundle of a digest-pinned Alpine image (verified clean:
        # alpine 3.22.7, 118 certificates, none of the four distrusted eMudhra
        # roots) into the in-memory volume. Busybox only: no package install,
        # no network at pod start.
        - name: filter-ca-certs
          image: "${INIT_IMAGE}"
          imagePullPolicy: IfNotPresent
          command: ["/bin/sh", "-ec"]
          env:
            - name: OUT_DIR
              value: /filtered-ca-certs
          volumeMounts:
            - name: filtered-ca-certs
              mountPath: /filtered-ca-certs
          securityContext:
            # Explicitly non-root: some add-ons (cert-manager) require non-root
            # without pinning a uid, which would reject this image's default
            # root user at admission. Any uid works: the source bundle is
            # world-readable and a Kubernetes emptyDir is mode 0777.
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            runAsNonRoot: true
            runAsUser: 65534
            capabilities:
              drop: ["ALL"]
            seccompProfile:
              type: RuntimeDefault
          resources:
            requests:
              cpu: 10m
              memory: 16Mi
            limits:
              memory: 64Mi
          terminationMessagePolicy: FallbackToLogsOnError
          args:
            - |
              SRC=/etc/ssl/certs/ca-certificates.crt
              [ -s "\$SRC" ] || { echo "ca-certs: FAIL: \$SRC missing or empty" >&2; exit 1; }
              n=\$(grep -c -- '-----BEGIN CERTIFICATE-----' "\$SRC")
              [ "\$n" -ge 100 ] || { echo "ca-certs: FAIL: only \$n certificates in \$SRC" >&2; exit 1; }
              cp "\$SRC" "\$OUT_DIR/ca-certificates.crt"
              echo "ca-certs: ok: installed \$n certificates from the pinned alpine 3.22 bundle"
YAML
}

# Rollback removes the init container, volume, and mount. It keeps the
# konnectivity agent's maxUnavailable 1 because the rollback is itself a
# rolling update and would deadlock without it on a 3-worker cluster.
rollback_patch_for() { # $1 container name
  cat <<YAML
spec:
  template:
    spec:
      volumes:
        - \$patch: delete
          name: filtered-ca-certs
      containers:
        - name: $1
          volumeMounts:
            - \$patch: delete
              mountPath: /etc/ssl/certs
      initContainers:
        - \$patch: delete
          name: filter-ca-certs
YAML
}

# ---------- preflight ----------
if [[ "$MODE" == print-patch ]]; then
  for entry in "${ADDONS[@]}"; do IFS='|' read -r name group ns deploy container selector strategy <<<"$entry"
    [[ "$name" == "$PRINT_ADDON" ]] && { patch_for "$container" "$strategy"; exit 0; }
  done
  echo "unknown add-on: $PRINT_ADDON" >&2
  printf 'known: ' >&2; for entry in "${ADDONS[@]}"; do printf '%s ' "${entry%%|*}" >&2; done; echo >&2
  exit 2
fi

command -v kubectl >/dev/null 2>&1 || { echo "kubectl not found in PATH" >&2; exit 2; }
if ! server=$(kc version -o json 2>/dev/null | sed -n 's/.*"gitVersion": *"\([^"]*\)".*/\1/p' | tail -1) || [[ -z "$server" ]]; then
  echo "$BAD cannot reach the cluster API with kubectl (check --kubeconfig/--context); nothing changed" >&2; exit 1
fi
echo "Cluster: Kubernetes $server"
case "$MODE" in
  apply)    echo "Mode:    apply (init image $INIT_IMAGE)";;
  dry-run)  echo "Mode:    dry run, nothing will change";;
  rollback) echo "Mode:    rollback";;
  list)     echo "Mode:    list, nothing will change";;
esac
echo

failures=0; applied=0; skipped=0
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

for entry in "${ADDONS[@]}"; do
  IFS='|' read -r name group ns deploy container selector strategy <<<"$entry"
  if [[ ${#ONLY[@]} -gt 0 ]]; then
    keep=no; for o in ${ONLY[@]+"${ONLY[@]}"}; do [[ "$o" == "$name" || "$o" == "$group" ]] && keep=yes; done
    [[ $keep == yes ]] || continue
  fi

  # ----- applicability -----
  if ! k "$ns" get deployment "$deploy" -o name >/dev/null 2>&1; then
    # the add-on may be installed in a different namespace (non-default Helm release)
    found_ns=$(kc get deployment -A --field-selector "metadata.name=$deploy" \
                 -o jsonpath='{range .items[*]}{.metadata.namespace}{" "}{end}' 2>/dev/null)
    set -- $found_ns
    if [[ $# -eq 1 ]]; then
      ns="$1"; note "$name: found in namespace $ns"
    elif k "$ns" get daemonset "$deploy" -o name >/dev/null 2>&1; then
      result "$SKIP" "$name" "runs as a DaemonSet managed by the Crusoe control plane; Crusoe will fix it in a control-plane release, no action needed"
      skipped=$((skipped+1)); continue
    else
      result "$SKIP" "$name" "not installed (no Deployment $ns/$deploy)"
      skipped=$((skipped+1)); continue
    fi
  fi

  # resolve the container name against the live Deployment, so a chart that
  # renames it (or a different add-on version) still works
  containers=$(k "$ns" get deployment "$deploy" -o jsonpath='{range .spec.template.spec.containers[*]}{.name}{" "}{end}')
  if [[ " $containers " != *" $container "* ]]; then
    set -- $containers
    if [[ $# -eq 1 ]]; then
      note "$name: container $container not found, using the Deployment's only container $1"
      container="$1"
    else
      result "$BAD" "$name" "cannot tell which container to patch (expected $container, found: $containers)"
      failures=$((failures+1)); continue
    fi
  fi

  inits=$(k "$ns" get deployment "$deploy" -o jsonpath='{.spec.template.spec.initContainers[*].name}' 2>/dev/null)
  has_fix=no; [[ " $inits " == *" filter-ca-certs "* ]] && has_fix=yes
  replicas=$(k "$ns" get deployment "$deploy" -o jsonpath='{.spec.replicas}')

  # A Deployment owned by the Crusoe control plane (Kamaji) is re-rendered in
  # full on every control-plane reconcile (upgrades, resizes, control-plane
  # releases), so a change made here would silently disappear later. Leave it
  # to the Crusoe release that ships the fix. Rollback is still allowed, so a
  # fix applied by hand earlier can be removed.
  managed=$(k "$ns" get deployment "$deploy" -o jsonpath='{.metadata.labels.kamaji\.clastix\.io/component}' 2>/dev/null)
  if [[ -n "$managed" && "$MODE" != rollback ]]; then
    result "$SKIP" "$name" "managed by the Crusoe control plane; Crusoe will fix it in a control-plane release, no action needed"
    skipped=$((skipped+1)); continue
  fi

  # Anything else already mounted at or under /etc/ssl/certs is usually a custom
  # CA bundle. The fix's mount would replace it (mounts merge by path) and the
  # rollback would then delete it, or a file mounted inside would hide the clean
  # bundle. Leave such an add-on alone.
  custom_ca=""
  for m in $(k "$ns" get deployment "$deploy" -o jsonpath="{range .spec.template.spec.containers[?(@.name==\"$container\")].volumeMounts[*]}{.name}={.mountPath}{\" \"}{end}"); do
    case "${m#*=}" in
      /etc/ssl/certs|/etc/ssl/certs/*) [[ "${m%%=*}" != filtered-ca-certs ]] && custom_ca="$custom_ca ${m%%=*} at ${m#*=}" ;;
    esac
  done
  custom_ca_msg="the $container container already mounts${custom_ca}, likely a custom CA bundle the fix would replace; remove the distrusted roots from that bundle instead"

  # ----- list -----
  if [[ "$MODE" == list ]]; then
    image=$(k "$ns" get deployment "$deploy" -o jsonpath="{.spec.template.spec.containers[?(@.name==\"$container\")].image}")
    if [[ $has_fix == yes ]]; then result "$OK" "$name" "fix applied ($ns, $replicas replicas, $image)"
    elif [[ -n "$custom_ca" ]]; then result "$BAD" "$name" "not fixed and will not be changed: $custom_ca_msg"
    else result "$SKIP" "$name" "not fixed ($ns, $replicas replicas, $image)"; fi
    skipped=$((skipped+1)); continue
  fi

  # ----- rollback -----
  if [[ "$MODE" == rollback ]]; then
    if [[ $has_fix == no ]]; then result "$SKIP" "$name" "fix not present, nothing to roll back"; skipped=$((skipped+1)); continue; fi
    rollback_patch_for "$container" > "$tmp/$name-rollback.yaml"
    if ! k "$ns" patch deployment "$deploy" --type strategic --patch-file "$tmp/$name-rollback.yaml" >/dev/null 2>"$tmp/err"; then
      result "$BAD" "$name" "rollback patch rejected: $(tr -d '\n' < "$tmp/err")"; failures=$((failures+1)); continue
    fi
    if k "$ns" rollout status "deployment/$deploy" --timeout="$TIMEOUT" >/dev/null 2>"$tmp/err"; then
      result "$OK" "$name" "fix removed, pods rolled back"; applied=$((applied+1))
    else
      result "$BAD" "$name" "rollback applied but the rollout did not finish within $TIMEOUT; check: kubectl -n $ns get pods -l $selector"
      failures=$((failures+1))
    fi
    continue
  fi

  # ----- apply / dry-run -----
  if [[ $has_fix == yes ]]; then result "$OK" "$name" "fix already applied (init container filter-ca-certs present)"; skipped=$((skipped+1)); continue; fi
  if [[ -n "$custom_ca" ]]; then result "$BAD" "$name" "not changed: $custom_ca_msg"; failures=$((failures+1)); continue; fi
  patch_for "$container" "$strategy" > "$tmp/$name.yaml"

  if [[ "$MODE" == dry-run ]]; then
    if k "$ns" patch deployment "$deploy" --type strategic --patch-file "$tmp/$name.yaml" --dry-run=server -o name >/dev/null 2>"$tmp/err"; then
      result "$OK" "$name" "patch accepted by the API server (dry run); would roll $replicas pods in $ns"
    else
      result "$BAD" "$name" "patch rejected: $(tr -d '\n' < "$tmp/err")"; failures=$((failures+1))
    fi
    continue
  fi

  echo "$name: applying"
  if ! k "$ns" patch deployment "$deploy" --type strategic --patch-file "$tmp/$name.yaml" >/dev/null 2>"$tmp/err"; then
    result "$BAD" "$name" "patch rejected, nothing changed: $(tr -d '\n' < "$tmp/err")"; failures=$((failures+1)); continue
  fi
  note "patched; waiting for the rolling restart (up to $TIMEOUT)"
  if ! k "$ns" rollout status "deployment/$deploy" --timeout="$TIMEOUT" >/dev/null 2>"$tmp/err"; then
    pending=$(k "$ns" get pods -l "$selector" --field-selector=status.phase!=Running -o name 2>/dev/null | head -1)
    result "$BAD" "$name" "rollout did not finish within $TIMEOUT; old pods keep serving. Inspect: kubectl -n $ns logs ${pending:-<new pod>} -c filter-ca-certs ; roll back with: $0 --rollback --only $name"
    failures=$((failures+1)); continue
  fi
  # Verify: every pod of the NEW generation ran the init container successfully,
  # and the mount is live. Pods left over from the previous generation can still
  # be terminating and still match the label selector, so skip any pod whose spec
  # does not carry the init container rather than counting it as a failure.
  ready=$(k "$ns" get deployment "$deploy" -o jsonpath='{.status.readyReplicas}')
  bad_pod=""; certs=""; good=0
  for p in $(k "$ns" get pods -l "$selector" -o name); do
    k "$ns" get "$p" -o jsonpath='{.spec.initContainers[*].name}' 2>/dev/null | grep -q filter-ca-certs || continue
    line=$(k "$ns" logs "$p" -c filter-ca-certs 2>/dev/null | grep '^ca-certs: ok' | head -1)
    if [[ -n "$line" ]]; then
      good=$((good+1)); certs=$(echo "$line" | sed -n 's/.*installed \([0-9]*\) certificates.*/\1/p')
    else
      bad_pod="$p"
    fi
  done
  mount=$(k "$ns" get deployment "$deploy" -o jsonpath="{.spec.template.spec.containers[?(@.name==\"$container\")].volumeMounts[?(@.mountPath==\"/etc/ssl/certs\")].name}")
  why=""
  [[ -n "$bad_pod" ]] && why="pod $bad_pod did not report a successful init container"
  [[ -z "$why" && $good -lt ${ready:-1} ]] && why="only $good of ${ready:-1} ready pods carry the fix"
  [[ -z "$why" && "$mount" != filtered-ca-certs ]] && why="the /etc/ssl/certs mount is ${mount:-missing}"
  if [[ -z "$why" ]]; then
    result "$OK" "$name" "fixed: ${ready:-?} pods rolled, clean bundle of ${certs:-?} certificates mounted over /etc/ssl/certs"
    applied=$((applied+1))
  else
    result "$BAD" "$name" "rolled out but verification failed: $why; roll back with: $0 --rollback --only $name"
    failures=$((failures+1))
  fi
done

echo
echo "Summary: $applied changed, $skipped skipped, $failures failed"
(( failures == 0 ))
