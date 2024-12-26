# Assume Role ID

Web service for SaaS provider research. Hosted at [https://assume-role-id.ryanjarv.sh](https://assume-role-id.ryanjarv.sh).

## Deploy

Update the following: 

* The PROFILE variable in the Makefile to the AWS CLI profile you want to use. 
* The DomainName and ValidationDomain constants in [cdk.go](./cdk.go) to the domain you want to use.
  * You'll need to be able to receive emails at ValidationDomain to validate the certificate.

Then run `make bootstrap && make deploy`.
