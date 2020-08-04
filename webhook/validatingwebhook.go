package webhook

import (
	"context"
	"fmt"
	"net/http"

	"github.com/aws/aws-sdk-go/service/securityhub"

	"golang.org/x/sync/errgroup"
	"golang.org/x/xerrors"
	corev1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/knqyf263/trivy-aws-enforcer/opa"
)

const (
	opaURL = "http://opa.opa"
	path   = "/v1/data/kubernetes/validating/securityhub/deny"
)

var (
	log = ctrl.Log.WithName("validator")

	ErrForbidden = xerrors.New("container forbidden")
)

// +kubebuilder:webhook:path=/validate-v1-pod,mutating=false,failurePolicy=fail,groups="",resources=pods,verbs=create;update,versions=v1,name=vpod.kb.io

// PodValidator validates Pods
type PodValidator struct {
	client  client.Client
	decoder *admission.Decoder
	svc     *securityhub.SecurityHub
}

func NewPodValidator(client client.Client) *PodValidator {
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))
	svc := securityhub.New(sess)
	return &PodValidator{
		client: client,
		svc:    svc,
	}
}

// PodValidator admits a pod iff a specific annotation exists.
func (v *PodValidator) Handle(ctx context.Context, req admission.Request) admission.Response {
	pod := &corev1.Pod{}

	err := v.decoder.Decode(req, pod)
	if err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}

	log.Info("Validating webhook", "pod name", pod.Name)
	for _, c := range pod.Spec.Containers {
		log.Info("Retrieving a list of findings...")
		result, err := v.svc.GetFindings(&securityhub.GetFindingsInput{
			Filters: &securityhub.AwsSecurityFindingFilters{
				ResourceId: []*securityhub.StringFilter{
					{
						Value:      aws.String(c.Image),
						Comparison: aws.String("EQUALS"),
					},
				},
			},
		})
		if err != nil {
			return admission.Errored(http.StatusInternalServerError, err)
		}

		log.Info("Fetched findings", "number", len(result.Findings))

		if len(result.Findings) == 0 {
			return admission.Denied(fmt.Sprintf("no scan result for image %s", c.Image))
		}

		log.Info("Evaluating vulnerabilities", "image name", c.Image)
		if err = evalFindings(ctx, path, c.Image, result.Findings); err != nil {
			log.Error(err, "evalFindings")
			if xerrors.Is(err, ErrForbidden) {
				return admission.Denied(err.Error())
			}
			return admission.Errored(http.StatusInternalServerError, err)
		}

	}
	return admission.Allowed("")
}

func evalFindings(ctx context.Context, path string, image string, inputs []*securityhub.AwsSecurityFinding) error {
	log.Info("Evaluate findings", "path", path, "input", len(inputs))
	o := opa.New(opaURL)
	limit := make(chan struct{}, 10)

	eg, ctx := errgroup.WithContext(ctx)
	for _, input := range inputs {
		vuln := input
		if *vuln.WorkflowState != "NEW" {
			continue
		}
		eg.Go(func() error {
			limit <- struct{}{}
			defer func() { <-limit }()

			result, err := o.Eval(ctx, path, vuln)
			if err != nil {
				return err
			}

			if len(result) != 0 {
				return xerrors.Errorf("%s in image %s: %w", result[0], image, ErrForbidden)
			}
			return nil
		})
	}

	if err := eg.Wait(); err != nil {
		return err
	}

	return nil
}

// podValidator implements admission.DecoderInjector.
// A decoder will be automatically injected.

// InjectDecoder injects the decoder.
func (v *PodValidator) InjectDecoder(d *admission.Decoder) error {
	v.decoder = d
	return nil
}
