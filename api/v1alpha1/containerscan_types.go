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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

const (
	EventSource                 = "ContainerScan"
	EventReasonIssuerReconciler = "ContainerScanReconciler"
)

// ContainerScanSpec defines the desired state of ContainerScan
type ContainerScanSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Containers in the target namespace will be monitored by the controller
	TargetNamespace string `json:"targetNamespace"`

	// Suspends email alerts if set to true, target email (.spec.email) will not be notified
	// +optional
	SuspendEmailAlert *bool `json:"suspendEmailAlert,omitempty"`

	// Target user's email for container status notification
	// +optional
	Email string `json:"email,omitempty"`

	// SMTP Relay host for sending the email
	// +optional
	RelayHost string `json:"relayHost,omitempty"`

	//aggregate external alerts per pod, if set to false, alarm will be raised for each problematic container
	AggregateAlerts *bool `json:"aggregateAlerts,omitempty"`
	// To notify the external alerting system, boolean (true, false). Set true to notify the external system.
	// +optional
	NotifyExtenal *bool `json:"notifyExternal,omitempty"`

	// URL of the external alert system
	// +optional
	ExternalURL string `json:"externalURL,omitempty"`

	// Data to be sent to the external system in the form of config map
	// +optional
	ExternalData string `json:"externalData,omitempty"`

	// Secret which has the username and password to post the alert notification to the external system
	// +optional
	ExternalSecret string `json:"externalSecret,omitempty"`
}

// ContainerScanStatus defines the observed state of ContainerScan
type ContainerScanStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
	// list of status conditions to indicate the status of managed cluster
	// known conditions are 'Ready'.
	// +optional
	Conditions []ContainerScanCondition `json:"conditions,omitempty"`

	// last successful timestamp of retrieved cluster status
	// +optional
	LastRunTime *metav1.Time `json:"lastRunTime,omitempty"`

	// Indicates if external alerting system is notified
	// +optional
	ExternalNotified bool `json:"externalNotified"`

	// Indicates the timestamp when external alerting system is notified
	// +optional
	ExternalNotifiedTime *metav1.Time `json:"externalNotifiedTime"`

	// Incident ID from the rem. Spark specific
	IncidentID string `json:"incidentID"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:resource:scope=Cluster

// ContainerScan is the Schema for the containerscans API
// +kubebuilder:printcolumn:name="CreatedAt",type="string",JSONPath=".metadata.creationTimestamp",description="object creation timestamp(in cluster's timezone)"
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[].status",description="if set to true, there is no container with non-zero terminate state"
// +kubebuilder:printcolumn:name="LastSuccessfulTime",type="string",JSONPath=".status.lastRunTime",description="last successful run (where there is no failed containers) timestamp(in cluster's timezone)"
// +kubebuilder:printcolumn:name="ExternalNotified",type="string",JSONPath=".status.externalNotified",description="indicates if the external system is notified"
// +kubebuilder:printcolumn:name="IncidentID",type="string",JSONPath=".status.incidentID",description="incident ID from service now"
type ContainerScan struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ContainerScanSpec   `json:"spec,omitempty"`
	Status ContainerScanStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// ContainerScanList contains a list of ContainerScan
type ContainerScanList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ContainerScan `json:"items"`
}

type ContainerScanCondition struct {
	// Type of the condition, known values are 'Ready'.
	Type ContainerScanConditionType `json:"type"`

	// Status of the condition, one of ('True', 'False', 'Unknown')
	Status ConditionStatus `json:"status"`

	// LastTransitionTime is the timestamp of the last update to the status
	// +optional
	LastTransitionTime *metav1.Time `json:"lastTransitionTime,omitempty"`

	// Reason is the machine readable explanation for object's condition
	// +optional
	Reason string `json:"reason,omitempty"`

	// Message is the human readable explanation for object's condition
	Message string `json:"message"`
}

// ManagedConditionType represents a managed cluster condition value.
type ContainerScanConditionType string

const (
	// ContainerScanConditionReady represents the fact that a given managed cluster condition
	// is in reachable from the ACM/source cluster.
	// If the `status` of this condition is `False`, managed cluster is unreachable
	ContainerScanConditionReady ContainerScanConditionType = "Ready"
)

// ConditionStatus represents a condition's status.
// +kubebuilder:validation:Enum=True;False;Unknown
type ConditionStatus string

// These are valid condition statuses. "ConditionTrue" means a resource is in
// the condition; "ConditionFalse" means a resource is not in the condition;
// "ConditionUnknown" means kubernetes can't decide if a resource is in the
// condition or not. In the future, we could add other intermediate
// conditions, e.g. ConditionDegraded.
const (
	// ConditionTrue represents the fact that a given condition is true
	ConditionTrue ConditionStatus = "True"

	// ConditionFalse represents the fact that a given condition is false
	ConditionFalse ConditionStatus = "False"

	// ConditionUnknown represents the fact that a given condition is unknown
	ConditionUnknown ConditionStatus = "Unknown"
)

func init() {
	SchemeBuilder.Register(&ContainerScan{}, &ContainerScanList{})
}
