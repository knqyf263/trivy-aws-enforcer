# trivy-aws-enforcer

## Setup

```
$ kubectl apply -f manifests/cert-manager.yaml
$ kubectl apply -f manifests/opa.yaml
$ make deploy
```

## Rego example

```
$ cat example/security_hub.rego
package kubernetes.validating.securityhub

deny[msg] {
    resource := input.Resources[_]
    details := resource.Details
    to_number(details.Other.NvdCvssV3Score) > 7.0
    msg := "critical vulnerability found"
}
```