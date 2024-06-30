package util

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/barani129/container-scan/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func GetSpecAndStatus(ContainerScan client.Object) (*v1alpha1.ContainerScanSpec, *v1alpha1.ContainerScanStatus, error) {
	switch t := ContainerScan.(type) {
	case *v1alpha1.ContainerScan:
		return &t.Spec, &t.Status, nil
	default:
		return nil, nil, fmt.Errorf("not a container scan type: %t", t)
	}
}

func GetReadyCondition(status *v1alpha1.ContainerScanStatus) *v1alpha1.ContainerScanCondition {
	for _, c := range status.Conditions {
		if c.Type == v1alpha1.ContainerScanConditionReady {
			return &c
		}
	}
	return nil
}

func IsReady(status *v1alpha1.ContainerScanStatus) bool {
	if c := GetReadyCondition(status); c != nil {
		return c.Status == v1alpha1.ConditionTrue
	}
	return false
}

func SetReadyCondition(status *v1alpha1.ContainerScanStatus, conditionStatus v1alpha1.ConditionStatus, reason, message string) {
	ready := GetReadyCondition(status)
	if ready == nil {
		ready = &v1alpha1.ContainerScanCondition{
			Type: v1alpha1.ContainerScanConditionReady,
		}
		status.Conditions = append(status.Conditions, *ready)
	}
	if ready.Status != conditionStatus {
		ready.Status = conditionStatus
		now := metav1.Now()
		ready.LastTransitionTime = &now
	}
	ready.Reason = reason
	ready.Message = message
	for i, c := range status.Conditions {
		if c.Type == v1alpha1.ContainerScanConditionReady {
			status.Conditions[i] = *ready
			return
		}
	}
}

func SendEmailAlert(podname string, contname string, spec *v1alpha1.ContainerScanSpec) {
	filename := fmt.Sprintf("%s-%s.txt", podname, contname)
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		message := fmt.Sprintf(`/bin/echo "Container %s in pod %s is terminated with exit code non-zero" | /usr/sbin/sendmail -f %s -S %s %s`, podname, contname, spec.Email, spec.RelayHost, spec.Email)
		cmd3 := exec.Command("/bin/bash", "-c", message)
		err := cmd3.Run()
		if err != nil {
			fmt.Printf("Failed to send the alert: %s", err)
		}
		writeFile(filename, "sent")
	} else {
		data, _ := ReadFile(filename)
		if data != "sent" {
			message := fmt.Sprintf(`/bin/echo "Container %s in pod %s is terminated with exit code non-zero" | /usr/sbin/sendmail -f %s -S %s %s`, podname, contname, spec.Email, spec.RelayHost, spec.Email)
			cmd3 := exec.Command("/bin/bash", "-c", message)
			err := cmd3.Run()
			if err != nil {
				fmt.Printf("Failed to send the alert: %s", err)
			}
		}

	}
}

func SendEmailRecoverAlert(podname string, contname string, spec *v1alpha1.ContainerScanSpec) {
	filename := fmt.Sprintf("%s-%s.txt", podname, contname)
	data, err := ReadFile(filename)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(data)
	if data == "sent" {
		message := fmt.Sprintf(`/bin/echo "Container %s in pod %s is recovered" | /usr/sbin/sendmail -f %s -S %s %s`, podname, contname, spec.Email, spec.RelayHost, spec.Email)
		cmd3 := exec.Command("/bin/bash", "-c", message)
		err := cmd3.Run()
		if err != nil {
			fmt.Printf("Failed to send the alert: %s", err)
		}
	}
}

func writeFile(filename string, data string) error {
	err := os.WriteFile(filename, []byte(data), 0644)
	if err != nil {
		return err
	}
	return nil
}

func ReadFile(filename string) (string, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func SubNotifyExternalSystem(data map[string]string, status string, url string, username string, password string, podname string, contname string, clstatus *v1alpha1.ContainerScanStatus) error {
	filename := fmt.Sprintf("%s-%s-ext.txt", podname, contname)
	var fingerprint string
	var err error
	if status == "resolved" {
		fingerprint, err = ReadFile(filename)
		if err != nil || fingerprint == "" {
			return fmt.Errorf("unable to notify the system for the %s status due to missing fingerprint in the file %s", status, filename)
		}
	} else {
		fingerprint, _ = ReadFile(filename)
		if fingerprint != "" {
			return nil
		}
		fingerprint = randomString(10)
	}
	data["fingerprint"] = fingerprint
	data["status"] = status
	data["startsAt"] = time.Now().String()
	m, b := data, new(bytes.Buffer)
	json.NewEncoder(b).Encode(m)
	var client *http.Client
	if strings.Contains(url, "https://") {
		tr := http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client = &http.Client{
			Timeout:   5 * time.Second,
			Transport: &tr,
		}
	}
	client = &http.Client{
		Timeout: 5 * time.Second,
	}
	req, err := http.NewRequest("POST", url, b)
	if err != nil {
		return err
	}
	req.Header.Add("Authorization", "Basic "+basicAuth(username, password))
	req.Header.Set("User-Agent", "Openshift")
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || resp == nil {
		return err
	}
	writeFile(filename, fingerprint)
	clstatus.ExternalNotified = true
	now := metav1.Now()
	clstatus.ExternalNotifiedTime = &now
	return nil
}

func randomString(length int) string {
	b := make([]byte, length+2)
	rand.Read(b)
	return fmt.Sprintf("%x", b)[2 : length+2]
}

func NotifyExternalSystem(data map[string]string, status string, url string, username string, password string, podname string, contname string, clstatus *v1alpha1.ContainerScanStatus) error {
	filename := fmt.Sprintf("%s-%s-ext.txt", podname, contname)
	fig, _ := ReadFile(filename)
	if fig != "" {
		log.Printf("External system has already been notified for pod %s and container %s . Exiting", podname, contname)
		return nil
	}
	fingerprint := randomString(10)
	data["fingerprint"] = fingerprint
	data["status"] = status
	data["startsAt"] = time.Now().String()
	m, b := data, new(bytes.Buffer)
	json.NewEncoder(b).Encode(m)
	var client *http.Client
	if strings.Contains(url, "https://") {
		tr := http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client = &http.Client{
			Timeout:   5 * time.Second,
			Transport: &tr,
		}
	}
	client = &http.Client{
		Timeout: 5 * time.Second,
	}
	req, err := http.NewRequest("POST", url, b)
	if err != nil {
		return err
	}
	req.Header.Add("Authorization", "Basic "+basicAuth(username, password))
	req.Header.Set("User-Agent", "Openshift")
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || resp == nil {
		return err
	}
	writeFile(filename, fingerprint)
	clstatus.ExternalNotified = true
	now := metav1.Now()
	clstatus.ExternalNotifiedTime = &now
	return nil
}

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}
