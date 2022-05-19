
# Check PDF Signature Attributes

A simple CLI software for checking attributes of Digital Signatures in PDF

## Features
- Support digital signatures with Filter Adobe.PPKLite and subfilter of:
  1. ETSI.CAdES.detached,
  2. adbe.pkcs7.detached,
  3. ETSI.RFC3161
- Using Java 8


## Build
Use mvn package to build the module into jar file
```shell
mvn clean package
```

## Explanation
You can find the detail explanation of this repository in [this medium blog](https://medium.com/javarevisited/simple-digital-signature-validation-on-pdf-17a66c1bf8d2).

## Usage
- This example used to check validity of a certificate through OCSP:
```shell
java -jar PDF-Tools.jar CheckSignature -p d:\test.pdf
```

## Feedback
For feedback and feature request, please raise issues in the issue section of the repository. Enjoy!!.