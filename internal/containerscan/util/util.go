package util

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
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

type RemResponse struct {
	ID                  int    `json:"id"`
	ServiceType         string `json:"ServiceType"`
	Summary             string `json:"Summary"`
	Acknowledged        int    `json:"Acknowledged"`
	Type                int    `json:"Type"`
	Location            string `json:"Location"`
	Node                string `json:"Node"`
	Note                string `json:"Note"`
	Severity            int    `json:"Severity"`
	Agent               string `json:"Agent"`
	AlertGroup          string `json:"AlertGroup"`
	NodeAlias           string `json:"NodeAlias"`
	Manager             string `json:"Manager"`
	EquipRole           string `json:"EquipRole"`
	Tally               int    `json:"Tally"`
	X733SpecificProb    string `json:"X733SpecificProb"`
	Oseventid           string `json:"OSEVENTID"`
	EquipType           string `json:"EquipType"`
	LastOccurrence      string `json:"LastOccurrence"`
	AlertKey            string `json:"AlertKey"`
	SourceServerName    string `json:"SourceServerName"`
	SuppressEscl        int    `json:"SuppressEscl"`
	CorrelationID       string `json:"CorrelationID"`
	Serial              string `json:"Serial"`
	Identifier          string `json:"Identifier"`
	Class               int    `json:"Class"`
	StateChange         string `json:"StateChange"`
	FirstOccurrence     string `json:"FirstOccurrence"`
	Grade               int    `json:"Grade"`
	Flash               int    `json:"Flash"`
	EventID             string `json:"EventId"`
	ExpireTime          int    `json:"ExpireTime"`
	Customer            string `json:"Customer"`
	NmosDomainName      string `json:"NmosDomainName"`
	X733EventType       int    `json:"X733EventType"`
	X733ProbableCause   string `json:"X733ProbableCause"`
	ServerName          string `json:"ServerName"`
	ServerSerial        int    `json:"ServerSerial"`
	ExtendedAttr        string `json:"ExtendedAttr"`
	OldRow              int    `json:"OldRow"`
	ProbeSubSecondID    int    `json:"ProbeSubSecondId"`
	CollectionFirst     any    `json:"CollectionFirst"`
	AggregationFirst    any    `json:"AggregationFirst"`
	DisplayFirst        any    `json:"DisplayFirst"`
	LocalObjRelate      int    `json:"LocalObjRelate"`
	RemoteTertObj       string `json:"RemoteTertObj"`
	RemoteObjRelate     int    `json:"RemoteObjRelate"`
	CorrScore           int    `json:"CorrScore"`
	CauseType           int    `json:"CauseType"`
	AdvCorrCauseType    int    `json:"AdvCorrCauseType"`
	AdvCorrServerName   string `json:"AdvCorrServerName"`
	AdvCorrServerSerial int    `json:"AdvCorrServerSerial"`
	TTNumber            string `json:"TTNumber"`
	TicketState         string `json:"TicketState"`
	JournalSent         int    `json:"JournalSent"`
	ProbeSerial         string `json:"ProbeSerial"`
	AdditionalText      string `json:"AdditionalText"`
	AlarmID             string `json:"AlarmID"`
	OriginalSeverity    int    `json:"OriginalSeverity"`
	SentToJDBC          int    `json:"SentToJDBC"`
	Service             string `json:"Service"`
	URL                 string `json:"url"`
	AutomationState     any    `json:"automationState"`
	Cleared             any    `json:"cleared"`
	DedupeColumns       any    `json:"dedupeColumns"`
	SuppressAggregation bool   `json:"suppressAggregation"`
	QueueMessageKey     any    `json:"queueMessageKey"`
	Aggregationaction   any    `json:"aggregationaction"`
	Correlationobject   any    `json:"correlationobject"`
	CorrelationNode     string `json:"correlationNode"`
	BaseNode            string `json:"baseNode"`
	Enrichment          any    `json:"Enrichment"`
}

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

func SendEmailAlert(podname string, contname string, spec *v1alpha1.ContainerScanSpec, filename string) {
	data, _ := ReadFile(filename)
	var message string
	if data != "sent" {
		if contname == "cont" {
			message = fmt.Sprintf(`/bin/echo "pod %s has containers with exit code non-zero" | /usr/sbin/sendmail -f %s -S %s %s`, podname, spec.Email, spec.RelayHost, spec.Email)
		} else {
			message = fmt.Sprintf(`/bin/echo "Container %s in pod %s is terminated with exit code non-zero" | /usr/sbin/sendmail -f %s -S %s %s`, podname, contname, spec.Email, spec.RelayHost, spec.Email)
		}
		cmd3 := exec.Command("/bin/bash", "-c", message)
		err := cmd3.Run()
		if err != nil {
			fmt.Printf("Failed to send the alert: %s", err)
		}
		writeFile(filename, "sent")
	}
}

func SendEmailRecoverAlert(podname string, contname string, spec *v1alpha1.ContainerScanSpec, filename string) {
	data, _ := ReadFile(filename)
	var message string
	if data == "sent" {
		if contname == "cont" {
			message = fmt.Sprintf(`/bin/echo "Containers in affected pod %s are recovered" | /usr/sbin/sendmail -f %s -S %s %s`, podname, spec.Email, spec.RelayHost, spec.Email)
		} else {
			message = fmt.Sprintf(`/bin/echo "Container %s in pod %s is recovered" | /usr/sbin/sendmail -f %s -S %s %s`, podname, contname, spec.Email, spec.RelayHost, spec.Email)
		}
		cmd3 := exec.Command("/bin/bash", "-c", message)
		err := cmd3.Run()
		if err != nil {
			fmt.Printf("Failed to send the alert: %s", err)
		}
	}
}

func writeFile(filename string, data string) error {
	err := os.WriteFile(filename, []byte(data), 0666)
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

func SubNotifyExternalSystem(data map[string]string, status string, url string, username string, password string, podname string, contname string, clstatus *v1alpha1.ContainerScanStatus, filename string) error {
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
	if contname == "cont" {
		data["alertName"] = fmt.Sprintf("pod %s has non-zero exit code containers, please check", podname)
		data["message"] = fmt.Sprintf("pod %s has non-zero exit code containers, please check", podname)
	} else {
		data["alertName"] = fmt.Sprintf("Container %s in pod %s has non-zero exit code, please check", contname, podname)
		data["message"] = fmt.Sprintf("Container %s in pod %s has non-zero exit code, please check", contname, podname)
	}
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

func NotifyExternalSystem(data map[string]string, status string, url string, username string, password string, podname string, contname string, clstatus *v1alpha1.ContainerScanStatus, filename string) error {
	fig, _ := ReadFile(filename)
	if fig != "" {
		log.Printf("External system has already been notified for pod %s and container %s . Exiting", podname, contname)
		return nil
	}
	fingerprint := randomString(10)
	data["fingerprint"] = fingerprint
	data["status"] = status
	data["startsAt"] = time.Now().String()
	if contname == "cont" {
		data["alertName"] = fmt.Sprintf("pod %s has non-zero exit code containers, please check", podname)
		data["message"] = fmt.Sprintf("pod %s has non-zero exit code containers, please check", podname)
	} else {
		data["alertName"] = fmt.Sprintf("Container %s in pod %s has non-zero exit code, please check", contname, podname)
		data["message"] = fmt.Sprintf("Container %s in pod %s has non-zero exit code, please check", contname, podname)
	}
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

func CreateFile(container string, pod string) error {
	_, err := os.OpenFile(fmt.Sprintf("/%s-%s.txt", container, pod), os.O_RDONLY|os.O_CREATE, 0666)
	if err != nil {
		return err
	}
	return nil
}

func CreateExtFile(container string, pod string) error {
	_, err := os.OpenFile(fmt.Sprintf("/%s-%s-ext.txt", container, pod), os.O_RDONLY|os.O_CREATE, 0666)
	if err != nil {
		return err
	}
	return nil
}

func SetIncidentID(spec *v1alpha1.ContainerScanSpec, status *v1alpha1.ContainerScanStatus, username string, password string, fingerprint string) (string, error) {
	url := spec.ExternalURL
	nurl := strings.SplitAfter(url, "co.nz")
	getUrl := nurl[0] + "/rem/api/event/v1/query"
	var client *http.Client
	if strings.Contains(getUrl, "https://") {
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
	req, err := http.NewRequest("GET", getUrl, nil)
	fmt.Println(req)
	if err != nil {
		return "", err
	}
	req.Header.Add("Authorization", "Basic "+basicAuth(username, password))
	req.Header.Set("Content-Type", "application/json")
	q := req.URL.Query()
	q.Add("alertKey", fingerprint)
	q.Add("maxalarms", "1")
	req.URL.RawQuery = q.Encode()
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	dat, err := io.ReadAll(resp.Body)
	sdata := string(dat)
	s1 := strings.TrimPrefix(sdata, "[")
	s2 := strings.TrimSuffix(s1, "]")
	if err != nil {
		return "", err
	}
	var x RemResponse
	err = json.Unmarshal([]byte(s2), &x)
	if err != nil {
		return "", err
	}
	status.IncidentID = x.TTNumber
	return x.TTNumber, nil
}
