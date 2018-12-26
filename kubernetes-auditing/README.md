
### Create users

Allowing an external user to be authenticated to the kubernetes cluster in order to create / update resources requires performing the following steps. 

Create a request specifying the details of the user which needs access to the cluster.  
```
cat << eof >> jai.json
{
    "CN": "user:jai",
    "key": {
        "algo": "ecdsa",
        "size": 256
    },
    "names": [
        {
            "C": "US",
            "L": "CA",
            "ST": "San Francisco",
            "O" : "system:users"
        }
    ]
}
eof
```
Generate the private key and the csr based on the request json. Alternatively, you can also use `cfssl print-defaults csr` and edit the json request file.  

```
cfssl genkey jai.json | cfssljson -bare certificate
```

With the csr and the private key generated, we now need to create a `CertificateSigningRequest` resource which is then approved/rejected by a cluster administrator to allow access to this user on the kubernetes cluster. 

The request is a base64 encoded string of the generated csr. 
```
cat certificate.csr | base64 | tr -d '\n'
```

Copy the above base64 encoded string and use that in the `CertificateSigningRequest`
```
apiVersion: certificates.k8s.io/v1beta1
kind: CertificateSigningRequest
metadata:
  name: user-jai
spec:
  groups:
  - system:authenticated
  request: <REDACTED> # base64 encoded csr
  usages:
  - digital signature
  - key encipherment
  - client auth
```

The new user certificate request needs to be approved, which essentially signs the user generated certificate by the cluster CA. 

> This step is performed by a cluster administrator

```
kubectl certificate approve user-jai
```

Get the signed certificate for the user. 
```
kubectl get csr user-jai -o jsonpath='{.status.certificate}' | base64 -d > jai.crt
```

Create a kubeconfig entry to be used to interact with the cluster using `kubectl` 
```
kubectl --kubeconfig ~/.kube/config-jai config set-cluster jai --insecure-skip-tls-verify=true --server=<apiserver url:6443>
kubectl --kubeconfig ~/.kube/config-jai config set-credentials jai --client-certificate=jai.crt --client-key=certificate-key.pem --embed-certs=true
kubectl --kubeconfig ~/.kube/config-jai config set-context jai --cluster=jai --user=jai
kubectl --kubeconfig ~/.kube/config-jai config use-context jai
```

These above steps will help prove the authenticity of the user. but the user still does not have any roles assigned to him. 
Create RBAC resources to provide access to the user either across namespaces or within a namespace. 

Provide the user `user:jai` edit permissions for all resources in the `default` namespace

```
cat << eof | kubectl apply -f -
kind: RoleBinding
apiVersion: rbac.authorization.k8s.io/v1beta1
metadata:
  name: jai-edit-rolebinding
  namespace: default
subjects:
- kind: User
  name: "user:jai"
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: edit
  apiGroup: rbac.authorization.k8s.io
eof
```

The user should be able to list pods in the default namespaces now. 
```
kubectl --kubeconfig ~/.kube/config-jai get pods
```

#### Enable auditing. 
The auditing needs to be enabled on the kube-apiserver hence ssh onto the node which runs the kube-apiserver. 

Create a folder which holds the audit policy 
```
mkdir -p /etc/kubernetes/auditpolicies
```
Place the `policy.yaml` spec in the above folder. We will volume mount this in the kube-apiserver pod spec. 

Enable auditing by adding the following options to the kube-apiserver podspec

```
    - --audit-policy-file=/etc/kubernetes/auditpolicies/policy.yaml
    - --audit-log-path=/var/log/audit.log
```

Refer `sample-kube-apiserver.yaml`

restarting the 


Deploy Elasticsearch and Kibana to ingest and visualize the logs. Fluentd would be used as the log shipper which publishes the audit log to an elasticsearch endpoint. You can use Helm or any other mechanism to deploy these components. 
There are yamls added in the same folder to deploy these components. The fluentd configmap requires mentioning the elasticsearch host endpoint (this can be obtained via kubectl get svc and presenting the clusterIP)