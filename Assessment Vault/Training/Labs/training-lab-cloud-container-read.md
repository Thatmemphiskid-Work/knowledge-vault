# Read-only cloud and container control-plane checks

## Prerequisites

Existing approved AWS CLI/kubectl installation and owner-provided read-only identities. Use only your allowed account, region, cluster and namespace. Do not install tools, obtain credentials or create resources. AWS IAM permissions and Kubernetes RBAC are different controls.

## AWS caller and bounded instance metadata

```sh
# Replace training-readonly and us-east-1 with the approved profile/region.
aws sts get-caller-identity --profile training-readonly --no-cli-pager
aws ec2 describe-instances --profile training-readonly --region us-east-1 --max-items 20 --query 'Reservations[].Instances[].{Id:InstanceId,State:State.Name}' --no-cli-pager
```

Protect account/identity metadata. Twenty items is a bounded inventory sample, not complete region/account coverage. A permission error does not prove no instances exist. Some API events require appropriate audit configuration.

## Kubernetes context, permission and one namespace

```sh
# Check context before making requests; stop if it is not the approved lab cluster.
kubectl config current-context
# Run these only after confirming context and allowed namespace.
kubectl auth can-i get pods --namespace training
kubectl get pods --namespace training -o custom-columns=NAME:.metadata.name,PHASE:.status.phase
```

Permission review and pod metadata only. No exec, deployment, secrets, role changes or host mounts. Namespace output is not complete cluster inventory and RBAC permission alone does not prove admission or workload safety.

## Operator and defender walkthrough

1. Record the approved identity/context before querying; stop on unexpected context rather than switching credentials automatically.
2. Run only the allowed read commands and capture resource identifiers, result and UTC time without secret material.
3. Defender: locate corresponding control-plane requests with actor, resource/namespace, action and result in the owner's audit tools.
4. Review provided inert workload manifests for privileged mode, host mounts and excessive roles; do not deploy them.
5. If inventory or audit is unavailable, record that gap. Repair read-role or collection configuration via the owner process and repeat the same query.

## Expected result

Only scoped resources are visible and corresponding read requests can be audited where required. Permission denial is an observed boundary, not inventory absence.

## What this does not prove

No container breakout, cloud writes, unmonitored-region deployment or logging tampering. Commands are not executed against AWS or Kubernetes during app verification.

[[Analyst Training]]