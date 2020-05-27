# Tool to decrypt AES-CBC-encrypted objects from etcd

This tool allows you to decrypt `aescbc` encrypted data from a Kubernetes etcd.

## Description

Kubernetes allows you to [encrypt Secret data at rest](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/), which means that the object data is stored in an encrypted form in etcd.

Once the `EncryptionConfiguration` is created and enabled with `--encryption-provider-config`, data is stored as follows in etcd:

```
"k8s:enc:<encryption-name>:v1:<provider-name>:<encrypted-data>"
```

For `aescbc` encrypted data, the `<encrypted-data>` consists of a 32-bit IV, followed by the AES blocks (PKCS#7 padded).

The recommended way to decrypt this data is to start a `kube-apiserver` with the correct `EncryptionConfig` and then to query the API to decrypt and retrieve the data. However, in some cases this might not be feasible, which is why this tool has been created to directly decrypt the data without a `kube-apiserver`.

## Build and run

```
$ go build .
$ ./k8s-etcd-decryptor
```

## Usage

To decrypt a certain object from a Kubernetes etcd, proceed as follows:

1) To extract the an object from `etcd`, use the following command inside the `etcd` container to set up the environment variables (often found in /etc/etcd/etcd.conf) and retrieve the base64-encoded `etcd` object (a `Secret` in this example):

   ```
   # source /etc/etcd/etcd.conf 
   # export ETCDCTL_API=3
   # etcdctl --cert=$ETCD_PEER_CERT_FILE --key=$ETCD_PEER_KEY_FILE --cacert $ETCD_TRUSTED_CA_FILE --endpoints=$ETCD_LISTEN_CLIENT_URLS get /kubernetes.io/secrets/simon-project/my-secret --write-out=json
   {"header":{"cluster_id":1535328224928523406,"member_id":10396734553733729853,"revision":30198,"raft_term":3},"kvs":[{"key":"L2t1YmVybmV0ZXMuaW8vc2VjcmV0cy9zaW1vbi1wcm9qZWN0L215LXNlY3JldA==","create_revision":28525,"mod_revision":28525,"version":1,"value":"azhzOmVuYzphZXNjYmM6djE6c2ltb246lvj7pYRT71cyo+aqLPjJ2kuvAOI4FghpUG5n405KRZOLnDU3EAw55jxDt+qAJPFArX7Jmp8wppRgdk7NE+3XiOCGnQBQWGkJX1irZ31DxotG4CfrxH4pJ0Agnmzw/e+bJAJGPO84SMFjrhInd14iseyErrfrG5s/dy0tEyDUtQMrVGMLkztYoELfBARK8+PP3H52oJmlM1rvU6jV09dbcQ=="}],"count":1}
   ```

2) Retrieve the base64-encoded "secret" from the `EncryptionConfig` in /etc/origin/master/encryption-config.yaml from your Master Nodes:

   ```
   # cat /etc/origin/master/encryption-config.yaml 
   kind: EncryptionConfig
   apiVersion: v1
   resources:
     - resources:
     - secrets
     - configmaps
     providers:
     - aescbc:
         keys:
         - name: "simon"
           secret: 1vTaJ76Pak2oXFu5k0muTN7Uo+VZWsV9caFjz/Pc3x4=
     - identity: {}
   ```

Using the `value` from the first step and the `secret` from the second step, you can then use the program in this repository to decrypt the object:

```
$ ./k8s-etcd-decryptor
Tool to decrypt AES-CBC-encrypted objects from etcd
Enter base64-encoded etcd value: azhzOmVuYzphZXNjYmM6djE6c2ltb246lvj7pYRT71cyo+aqLPjJ2kuvAOI4FghpUG5n405KRZOLnDU3EAw55jxDt+qAJPFArX7Jmp8wppRgdk7NE+3XiOCGnQBQWGkJX1irZ31DxotG4CfrxH4pJ0Agnmzw/e+bJAJGPO84SMFjrhInd14iseyErrfrG5s/dy0tEyDUtQMrVGMLkztYoELfBARK8+PP3H52oJmlM1rvU6jV09dbcQ==
Enter base64-encoded encryption key from EncryptionConfig: 1vTaJ76Pak2oXFu5k0muTN7Uo+VZWsV9caFjz/Pc3x4=
k8s


v1Secretv
T
simon-project"*$6567b48b-9f45-11ea-8fb6-fa163e827b272z
mysupersecretOpaque"
```

This will show the object (a `Secret` in this case) as a string, which is not very nice but works well for most use-cases.