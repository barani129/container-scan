/*
Copyright 2024 baranitharan.chittharanjan@spark.co.nz.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/barani129/container-scan/api/v1alpha1"
	monitoringv1alpha1 "github.com/barani129/container-scan/api/v1alpha1"
	"github.com/barani129/container-scan/internal/containerscan/util"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/client-go/rest"
)

const (
	defaultHealthCheckInterval = 2 * time.Minute
)

var (
	errGetNamespace     = errors.New("failed to get the target namespace in the cluster")
	errGetAuthSecret    = errors.New("failed to get Secret containing External alert system credentials")
	errGetAuthConfigMap = errors.New("failed to get ConfigMap containing the data to be sent to the external alert system")
)

// ContainerScanReconciler reconciles a ContainerScan object
type ContainerScanReconciler struct {
	client.Client
	Scheme                   *runtime.Scheme
	Kind                     string
	ClusterResourceNamespace string
	recorder                 record.EventRecorder
}

// +kubebuilder:rbac:groups=monitoring.spark.co.nz,resources=containerscans,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=monitoring.spark.co.nz,resources=containerscans/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=monitoring.spark.co.nz,resources=containerscans/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
func (r *ContainerScanReconciler) newContainer() (client.Object, error) {
	ContainerScanGVK := monitoringv1alpha1.GroupVersion.WithKind(r.Kind)
	ro, err := r.Scheme.New(ContainerScanGVK)
	if err != nil {
		return nil, err
	}
	return ro.(client.Object), nil
}

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the ContainerScan object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.17.2/pkg/reconcile
func (r *ContainerScanReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, err error) {
	_ = log.FromContext(ctx)

	// TODO(user): your logic here
	containerScan, err := r.newContainer()
	if err != nil {
		log.Log.Error(err, "unrecognized container scan type")
		return ctrl.Result{}, err
	}

	if err := r.Get(ctx, req.NamespacedName, containerScan); err != nil {
		if err := client.IgnoreNotFound(err); err != nil {
			return ctrl.Result{}, fmt.Errorf("unexpected get error : %v", err)
		}
		log.Log.Info("Container scan resource is not found, ignoring")
		return ctrl.Result{}, nil
	}

	containerSpec, containerStatus, err := util.GetSpecAndStatus(containerScan)
	if err != nil {
		log.Log.Error(err, "unexpected error while getting container scan spec and status, not trying.")
		return ctrl.Result{}, nil
	}

	// report gives feedback by updating the Ready condition of the Container scan
	report := func(conditionStatus monitoringv1alpha1.ConditionStatus, message string, err error) {
		eventType := corev1.EventTypeNormal
		if err != nil {
			log.Log.Error(err, message)
			eventType = corev1.EventTypeWarning
			message = fmt.Sprintf("%s: %v", message, err)
		} else {
			log.Log.Info(message)
		}
		r.recorder.Event(containerScan, eventType, monitoringv1alpha1.EventReasonIssuerReconciler, message)
		util.SetReadyCondition(containerStatus, conditionStatus, monitoringv1alpha1.EventReasonIssuerReconciler, message)
	}

	defer func() {
		if err != nil {
			report(monitoringv1alpha1.ConditionFalse, fmt.Sprintf("One or more containers have non-zero terminated in namespace %s", containerSpec.TargetNamespace), err)
		}
		if updateErr := r.Status().Update(ctx, containerScan); updateErr != nil {
			err = utilerrors.NewAggregate([]error{err, updateErr})
			result = ctrl.Result{}
		}
	}()
	var username string
	var password string
	var data map[string]string
	if *containerSpec.NotifyExtenal {
		secretName := types.NamespacedName{
			Name: containerSpec.ExternalSecret,
		}

		configmapName := types.NamespacedName{
			Name: containerSpec.ExternalData,
		}

		switch containerScan.(type) {
		case *monitoringv1alpha1.ContainerScan:
			secretName.Namespace = r.ClusterResourceNamespace
			configmapName.Namespace = r.ClusterResourceNamespace
		default:
			log.Log.Error(fmt.Errorf("unexpected issuer type: %s", containerScan), "not retrying")
			return ctrl.Result{}, nil
		}
		var secret corev1.Secret
		var configmap corev1.ConfigMap
		if err := r.Get(ctx, secretName, &secret); err != nil {
			return ctrl.Result{}, fmt.Errorf("%w, secret name: %s, reason: %v", errGetAuthSecret, secretName, err)
		}
		username = string(secret.Data["username"])
		password = string(secret.Data["password"])
		if err := r.Get(ctx, configmapName, &configmap); err != nil {
			return ctrl.Result{}, fmt.Errorf("%w, configmap name: %s, reason: %v", errGetAuthConfigMap, configmapName, err)
		}
		data = configmap.Data

	}

	if ready := util.GetReadyCondition(containerStatus); ready == nil {
		report(monitoringv1alpha1.ConditionUnknown, "First Seen", nil)
		return ctrl.Result{}, nil
	}
	actualNamespace := containerSpec.TargetNamespace
	config, err := rest.InClusterConfig()
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("unable to retrieve in cluster configuration due to %s", err)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("unable to retrieve in cluster configuration due to %s", err)
	}

	// pods, err := clientset.CoreV1().Pods(actualNamespace).List(context.TODO(), metav1.ListOptions{})
	// if err != nil {
	// 	return ctrl.Result{}, fmt.Errorf("unable to retrieve the pods in the namespace %s %s", actualNamespace, err)
	// }

	// for _, pod := range pods.Items {
	// 	for _, container := range pod.Spec.Containers {
	// 		err := util.CreateFile(container.Name, pod.Name)
	// 		if err != nil {
	// 			log.Log.Info("Unable to create the file")
	// 		}
	// 		err = util.CreateExtFile(container.Name, pod.Name)
	// 		if err != nil {
	// 			log.Log.Info("Unable to create the external file")
	// 		}
	// 	}
	// }

	if containerStatus.LastRunTime == nil {
		var afcontainers []string
		var afpods []string
		log.Log.Info("Checking for containers that havee exited with non-zero code")
		ns, err := clientset.CoreV1().Namespaces().Get(ctx, actualNamespace, metav1.GetOptions{})
		if err != nil || ns.Name != actualNamespace {
			return ctrl.Result{}, fmt.Errorf("%w, namespace: %s, reason: %v", errGetNamespace, actualNamespace, err)
		}
		pods, err := clientset.CoreV1().Pods(actualNamespace).List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("unable to retrieve the pods in the namespace %s %s", actualNamespace, err)
		}
		for _, pod := range pods.Items {
			for _, container := range pod.Status.ContainerStatuses {
				if container.State.Terminated != nil {
					if container.State.Terminated.ExitCode != 0 {
						if *containerSpec.AggregateAlerts {
							err := util.CreateFile("pod", pod.Name)
							if err != nil {
								log.Log.Info("Unable to create the file")
							}
							err = util.CreateExtFile("pod", pod.Name)
							if err != nil {
								log.Log.Info("Unable to create the external file")
							}
							afpods = append(afpods, container.Name)
							if !*containerSpec.SuspendEmailAlert {
								util.SendEmailAlert(pod.Name, "cont", containerSpec, fmt.Sprintf("/%s-%s.txt", "pod", pod.Name))
							}
							if *containerSpec.NotifyExtenal {
								err := util.NotifyExternalSystem(data, "firing", containerSpec.ExternalURL, username, password, pod.Name, "cont", containerStatus, fmt.Sprintf("/%s-%s-ext.txt", "pod", pod.Name))
								if err != nil {
									log.Log.Info("Failed to notify the external system for pod %s", pod.Name)
								}
								fingerprint, err := util.ReadFile(fmt.Sprintf("/%s-%s-ext.txt", "pod", pod.Name))
								if err != nil {
									log.Log.Info("Failed to update the incident ID. Couldn't find the fingerprint in the file")
								}
								incident, err := util.SetIncidentID(containerSpec, containerStatus, username, password, fingerprint)
								if err != nil || incident == "" {
									log.Log.Info("Failed to update the incident ID, either incident is getting created or other issues.")
								}
								containerStatus.IncidentID = incident
							}
						} else {
							err := util.CreateFile(container.Name, pod.Name)
							if err != nil {
								log.Log.Info("Unable to create the file")
							}
							err = util.CreateExtFile(container.Name, pod.Name)
							if err != nil {
								log.Log.Info("Unable to create the external file")
							}
							afcontainers = append(afcontainers, container.Name)
							if !*containerSpec.SuspendEmailAlert {
								util.SendEmailAlert(pod.Name, container.Name, containerSpec, fmt.Sprintf("/%s-%s.txt", container.Name, pod.Name))
							}
							if *containerSpec.NotifyExtenal {
								err := util.NotifyExternalSystem(data, "firing", containerSpec.ExternalURL, username, password, pod.Name, container.Name, containerStatus, fmt.Sprintf("/%s-%s-ext.txt", container.Name, pod.Name))
								if err != nil {
									log.Log.Info("Failed to notify the external system for pod %s and container %s", pod.Name, container.Name)
								}
								fingerprint, err := util.ReadFile(fmt.Sprintf("/%s-%s-ext.txt", container.Name, pod.Name))
								fmt.Println(fingerprint)
								if err != nil {
									log.Log.Info("Failed to update the incident ID. Couldn't find the fingerprint in the file")
								}
								incident, err := util.SetIncidentID(containerSpec, containerStatus, username, password, fingerprint)
								if err != nil || incident == "" {
									log.Log.Info("Failed to update the incident ID, either incident is getting created or other issues.")
								}
								containerStatus.IncidentID = incident
							}
						}
					}
				}
			}
		}
		if *containerSpec.AggregateAlerts {
			if len(afpods) > 0 {
				return ctrl.Result{}, fmt.Errorf("containers with non-zero exit code found in namespace %s", actualNamespace)
			} else {
				now := metav1.Now()
				containerStatus.LastRunTime = &now
				afcontainers = nil
				err := remoteFiles(*clientset, actualNamespace, containerSpec)
				if err != nil {
					log.Log.Error(err, "unable to retrieve the pods")
				}
				report(monitoringv1alpha1.ConditionTrue, fmt.Sprintf("Success. All containers in the target namespace %s have running/zero terminated state", actualNamespace), nil)
			}
		} else {
			if len(afcontainers) > 0 {
				return ctrl.Result{}, fmt.Errorf("containers with non-zero exit code found in namespace %s", actualNamespace)
			} else {
				now := metav1.Now()
				containerStatus.LastRunTime = &now
				afcontainers = nil
				err := remoteFiles(*clientset, actualNamespace, containerSpec)
				if err != nil {
					log.Log.Error(err, "unable to retrieve the pods")
				}
				report(monitoringv1alpha1.ConditionTrue, fmt.Sprintf("Success. All containers in the target namespace %s have running/zero terminated state", actualNamespace), nil)
			}
		}
	} else {
		var affcontainers []string
		var affpods []string
		pastTime := time.Now().Add(-1 * defaultHealthCheckInterval)
		timeDiff := containerStatus.LastRunTime.Time.Before(pastTime)
		if timeDiff {
			log.Log.Info("Checking for containers that havee exited with non-zero code as the time elapsed")
			ns, err := clientset.CoreV1().Namespaces().Get(ctx, actualNamespace, metav1.GetOptions{})
			if err != nil || ns.Name != actualNamespace {
				return ctrl.Result{}, fmt.Errorf("%w, namespace: %s, reason: %v", errGetNamespace, actualNamespace, err)
			}
			pods, err := clientset.CoreV1().Pods(actualNamespace).List(context.TODO(), metav1.ListOptions{})
			if err != nil {
				return ctrl.Result{}, fmt.Errorf("unable to retrieve the pods in the namespace %s %s", actualNamespace, err)
			}
			for _, pod := range pods.Items {
				for _, container := range pod.Status.ContainerStatuses {
					if container.State.Terminated != nil {
						if container.State.Terminated.ExitCode != 0 {
							if *containerSpec.AggregateAlerts {
								err := util.CreateFile("pod", pod.Name)
								if err != nil {
									log.Log.Info("Unable to create the file")
								}
								err = util.CreateExtFile("pod", pod.Name)
								if err != nil {
									log.Log.Info("Unable to create the external file")
								}
								affpods = append(affpods, pod.Name)
								if !*containerSpec.SuspendEmailAlert {
									util.SendEmailAlert(pod.Name, "cont", containerSpec, fmt.Sprintf("/%s-%s.txt", "pod", pod.Name))
								}
								if *containerSpec.NotifyExtenal {
									err := util.SubNotifyExternalSystem(data, "firing", containerSpec.ExternalURL, username, password, pod.Name, "cont", containerStatus, fmt.Sprintf("/%s-%s-ext.txt", "pod", pod.Name))
									if err != nil {
										log.Log.Info("Failed to notify the external system for pod %s", pod.Name)
									}
									fingerprint, err := util.ReadFile(fmt.Sprintf("/%s-%s-ext.txt", "pod", pod.Name))
									if err != nil {
										log.Log.Info("Failed to update the incident ID. Couldn't find the fingerprint in the file")
									}
									incident, err := util.SetIncidentID(containerSpec, containerStatus, username, password, fingerprint)
									if err != nil || incident == "" {
										log.Log.Info("Failed to update the incident ID, either incident is getting created or other issues.")
									}
									containerStatus.IncidentID = incident
								}
							} else {
								affcontainers = append(affcontainers, container.Name)
								if !*containerSpec.SuspendEmailAlert {
									util.SendEmailAlert(pod.Name, container.Name, containerSpec, fmt.Sprintf("/%s-%s.txt", container.Name, pod.Name))
								}
								if *containerSpec.NotifyExtenal {
									err := util.SubNotifyExternalSystem(data, "firing", containerSpec.ExternalURL, username, password, pod.Name, container.Name, containerStatus, fmt.Sprintf("/%s-%s-ext.txt", container.Name, pod.Name))
									if err != nil {
										log.Log.Info("Failed to notify the external system for pod %s and container %s", pod.Name, container.Name)
									}
									fingerprint, err := util.ReadFile(fmt.Sprintf("/%s-%s-ext.txt", container.Name, pod.Name))
									fmt.Println(fingerprint)
									if err != nil {
										log.Log.Info("Failed to update the incident ID. Couldn't find the fingerprint in the file")
									}
									incident, err := util.SetIncidentID(containerSpec, containerStatus, username, password, fingerprint)
									if err != nil || incident == "" {
										log.Log.Info("Failed to update the incident ID, either incident is getting created or other issues.")
									}
									containerStatus.IncidentID = incident
								}
							}
						} else {
							if *containerSpec.AggregateAlerts {
								if !*containerSpec.SuspendEmailAlert {
									util.SendEmailRecoverAlert(pod.Name, "cont", containerSpec, fmt.Sprintf("/%s-%s.txt", container.Name, pod.Name))
								}
								if *containerSpec.NotifyExtenal {
									err := util.SubNotifyExternalSystem(data, "resolved", containerSpec.ExternalURL, username, password, pod.Name, container.Name, containerStatus, fmt.Sprintf("/%s-%s-ext.txt", container.Name, pod.Name))
									if err != nil {
										log.Log.Info("Failed to notify the external system for pod %s", pod.Name)
									}
									containerStatus.IncidentID = ""
								}
							} else {
								if !*containerSpec.SuspendEmailAlert {
									util.SendEmailRecoverAlert(pod.Name, container.Name, containerSpec, fmt.Sprintf("/%s-%s.txt", container.Name, pod.Name))
								}
								if *containerSpec.NotifyExtenal {
									err := util.SubNotifyExternalSystem(data, "resolved", containerSpec.ExternalURL, username, password, pod.Name, container.Name, containerStatus, fmt.Sprintf("/%s-%s-ext.txt", container.Name, pod.Name))
									if err != nil {
										log.Log.Info("Failed to notify the external system for pod %s and container %s", pod.Name, container.Name)
									}
									containerStatus.IncidentID = ""
								}
							}

						}
					} else if container.State.Running != nil {
						if *containerSpec.AggregateAlerts {
							if !*containerSpec.SuspendEmailAlert {
								util.SendEmailRecoverAlert(pod.Name, "cont", containerSpec, fmt.Sprintf("/%s-%s.txt", container.Name, pod.Name))
							}
							if *containerSpec.NotifyExtenal {
								err := util.SubNotifyExternalSystem(data, "resolved", containerSpec.ExternalURL, username, password, pod.Name, container.Name, containerStatus, fmt.Sprintf("/%s-%s-ext.txt", container.Name, pod.Name))
								if err != nil {
									log.Log.Info("Failed to notify the external system for pod %s and container %s", pod.Name, container.Name)
								}
								containerStatus.IncidentID = ""
							}
						} else {
							if !*containerSpec.SuspendEmailAlert {
								util.SendEmailRecoverAlert(pod.Name, container.Name, containerSpec, fmt.Sprintf("/%s-%s.txt", container.Name, pod.Name))
							}
							if *containerSpec.NotifyExtenal {
								err := util.SubNotifyExternalSystem(data, "resolved", containerSpec.ExternalURL, username, password, pod.Name, container.Name, containerStatus, fmt.Sprintf("/%s-%s-ext.txt", container.Name, pod.Name))
								if err != nil {
									log.Log.Info("Failed to notify the external system for pod %s and container %s", pod.Name, container.Name)
								}
								containerStatus.IncidentID = ""
							}
						}
					}
				}
			}
			if *containerSpec.AggregateAlerts {
				if len(affpods) > 0 {
					return ctrl.Result{}, fmt.Errorf("containers with non-zero exit code found in namespace %s", actualNamespace)
				} else {
					now := metav1.Now()
					containerStatus.LastRunTime = &now
					affcontainers = nil
					err := remoteFiles(*clientset, actualNamespace, containerSpec)
					if err != nil {
						log.Log.Error(err, "unable to retrieve the pods")
					}
					report(monitoringv1alpha1.ConditionTrue, fmt.Sprintf("Success. All containers in the target namespace %s have running/zero terminated state", actualNamespace), nil)
				}
			} else {
				if len(affcontainers) > 0 {
					return ctrl.Result{}, fmt.Errorf("containers with non-zero exit code found in namespace %s", actualNamespace)
				}
				now := metav1.Now()
				containerStatus.LastRunTime = &now
				err = remoteFiles(*clientset, actualNamespace, containerSpec)
				if err != nil {
					log.Log.Error(err, "unable to retrieve the pods")
				}
				report(monitoringv1alpha1.ConditionTrue, fmt.Sprintf("Success. All containers in the target namespace %s have running/zero terminated state", actualNamespace), nil)
			}

		}
	}
	return ctrl.Result{RequeueAfter: defaultHealthCheckInterval}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ContainerScanReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.recorder = mgr.GetEventRecorderFor(monitoringv1alpha1.EventSource)
	return ctrl.NewControllerManagedBy(mgr).
		For(&monitoringv1alpha1.ContainerScan{}).
		Complete(r)
}

func remoteFiles(clientset kubernetes.Clientset, namespace string, spec *v1alpha1.ContainerScanSpec) error {
	pods, err := clientset.CoreV1().Pods(namespace).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, pod := range pods.Items {
		for _, container := range pod.Spec.Containers {
			if *spec.AggregateAlerts {
				os.Remove(fmt.Sprintf("/%s-%s-ext.txt", "pod", pod.Name))
				os.Remove(fmt.Sprintf("/%s-%s.txt", "pod", pod.Name))
			} else {
				os.Remove(fmt.Sprintf("/%s-%s-ext.txt", container.Name, pod.Name))
				os.Remove(fmt.Sprintf("/%s-%s.txt", container.Name, pod.Name))
			}

		}
	}
	return nil
}
