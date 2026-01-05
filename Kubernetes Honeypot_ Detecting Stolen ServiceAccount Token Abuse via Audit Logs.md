# **Kubernetes Honeypot: Detecting Stolen ServiceAccount Token Abuse via Audit Logs**

I built a Kubernetes deception (honeypot) to detect real attacker behavior after a container compromise:

* Theft of a ServiceAccount token

* Unauthorized Kubernetes API access

* Early-stage attacker reconnaissance

The detection is based on **Kubernetes Audit Logs**, and sends **real-time Slack alerts** when triggered.

This setup works on **any Kubernetes distribution** (EKS, AKS, GKE, kubeadm).

---

##  **Why This Matters (Problem Statement)**

In real Kubernetes breaches, attackers almost never start by “exploiting Kubernetes”.
They start by living off the cluster.

Instead, they:

1. Compromise a container

2. Read the mounted ServiceAccount token

3. Use it to call the Kubernetes API

4. Enumerate permissions, pods, secrets, and nodes

###  

### 
### Before Deception

Without any deception in place:

- Stolen ServiceAccount tokens are used quietly
- Failed API calls (`403 Forbidden`) are ignored
- Detection happens late, after secrets or workloads are touched

### After Deception

With a decoy ServiceAccount:

- Any API call using the token is suspicious
- Even failed requests generate high-signal audit logs
- Detection happens at the **reconnaissance stage**

---

##  **Detection Goal**

The idea is simple:
Create a ServiceAccount that no legitimate workload should ever touch — and alert the moment it’s used.

* Whether via `kubectl`

* Or direct API calls using `curl`

* Or impersonation attempts

---

##  **Architecture Overview**

`Attacker / Tester`  
   `|`  
   `| steals ServiceAccount token`  
   `|`  
   `| calls Kubernetes API`  
   `|`  
   `v`  
`Kubernetes API Server`  
   `|`  
   `| logs request in audit.log`  
   `|`  
   `v`  
`Audit Log Monitor Script`  
   `|`  
   `v`  
`Slack Alert + alert.txt`

---

##  ** Create a Honeypot Namespace**

`kubectl create namespace honeypot`

This keeps all decoys isolated and easy to monitor.  
![Screenshot](images/image%20%288%29.png)
---

##  ** Create a Decoy ServiceAccount**

`apiVersion: v1`  
`kind: ServiceAccount`  
`metadata:`  
  `name: backup-sa`  
  `namespace: honeypot`

### **Why `backup-sa`?**

In real environments, attackers often assume anything related to backup, admin, or ops is high-value. 
This name looks **high-value and realistic** worth stealing — exactly what we want.

---

##  **Create a ServiceAccount Token**

`apiVersion: v1`  
`kind: Secret`  
`metadata:`  
  `name: backup-sa-token`  
  `namespace: honeypot`  
  `annotations:`  
    `kubernetes.io/service-account.name: backup-sa`  
`type: kubernetes.io/service-account-token`

After a few seconds, Kubernetes populates the JWT token automatically. This token is **cluster-valid** and No permissions are required for detection.

---

##  **Deploy a Decoy Pod That Exposes the Token**

`apiVersion: v1`  
`kind: Pod`  
`metadata:`  
  `name: file-backup`  
  `namespace: honeypot`  
`spec:`  
  `containers:`  
  `- name: backup`  
    `image: busybox`  
    `command: ["sh", "-c", "sleep 999999"]`  
    `volumeMounts:`  
    `- name: fake-token`  
      `mountPath: /opt/backup`  
      `readOnly: true`  
  `volumes:`  
  `- name: fake-token`  
    `secret:`  
      `secretName: backup-sa-token`

Looks like a normal backup job. This pod does not need to do anything malicious — its only purpose is to look carelessly configured.

### 

### 

### 

### **Why `/opt/backup/token`?**

Attackers commonly search:

* `/opt`

* `/backup`

* misconfigured secret paths

This mimics **real-world secret leakage**.   
![Screenshot](images/image%20%2811%29.png)  
![Screenshot](images/image%20%2810%29.png)

---

##  ** Ensure the ServiceAccount Has NO Permissions**

`kubectl auth can-i --list \`  
  `--as=system:serviceaccount:honeypot:backup-sa`

The ServiceAccount intentionally has zero permissions.
Even though every API request will fail, the audit log is still generated, which is all the signal we need. 
![Screenshot](images/image%20%2812%29.png)

---

##  **Enable Kubernetes Audit Logging**

Audit logging is required to observe API abuse.

Minimal policy:

`apiVersion: audit.k8s.io/v1`  
`kind: Policy`  
`rules:`  
`- level: Metadata`

Managed Kubernetes (EKS / AKS / GKE) already has audit logs enabled.  
![Screenshot](images/image%20%289%29.png)

---

##  **Trigger the Honeypot (Real Attacker Behavior)**

### **Steal the token**

`kubectl exec -n honeypot file-backup -- cat /opt/backup/token`  
![Screenshot](images/image%20%2813%29.png)

### **Call Kubernetes API using the stolen token**

`curl -k \`  
  `-H "Authorization: Bearer $TOKEN" \`  
  `https://kubernetes.default.svc/api/v1/namespaces`

Even if the response is:

`403 Forbidden`

 **The audit log is generated**, which is all we need.  
![Screenshot](images/image%20%2814%29.png)

---

##  **Audit Log Evidence**

Sample audit log entry:

`"user": {`  
  `"username": "system:serviceaccount:honeypot:backup-sa"`  
`},`  
`"verb": "list",`  
`"requestURI": "/api/v1/namespaces",`  
`"sourceIPs": ["192.168.102.158"]`

This ServiceAccount **should never be used legitimately**.

---

##  **Detection Script**

I used a lightweight Bash script to continuously watch the audit log for any reference to the honeypot ServiceAccount.

* Watches for the honeypot ServiceAccount

* Writes to `alert.txt`

* Sends a Slack alert

Detection logic:

`IF user.username OR impersonatedUser.username`  
`CONTAINS honeypot ServiceAccount`  
`→ ALERT`

This catches:

* Token theft

* Impersonation

* Reconnaissance

![Screenshot](images/image%20%286%29.png)
![Screenshot](images/image%20%287%29.png)

## Why This Works in Real Environments

- No kernel modules
- No admission controllers
- No agents inside workloads
- Works with managed Kubernetes audit logs
- Detects abuse even when permissions are zero

Most importantly, it detects attackers **before** they achieve impact
