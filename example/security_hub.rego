package kubernetes.validating.securityhub

deny[msg] {
    resource := input.Resources[_]
    details := resource.Details
    to_number(details.Other.NvdCvssV3Score) > 7.0
    msg := "critical vulnerability found"
}
