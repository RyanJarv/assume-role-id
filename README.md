# Assume Role ID

Web service for generating IAM roles. Hosted at [https://id.assume.ryanjarv.sh](https://id.assume.ryanjarv.sh).

## Deploy

Update the following: 

TODO: Update this

* The PROFILE variable in the Makefile to the AWS CLI profile you want to use. 
* The DomainName and ValidationDomain constants in [cdk.go](./cdk.go) to the domain you want to use.
  * You'll need to be able to receive emails at ValidationDomain to validate the certificate.
  * The deployment will pause until you validate the certificate.

Then run `make bootstrap && make deploy`.


## Notes

Some of the PrincipalId lookup code was initially borrowed from [ak2-au/awsid](https://github.com/ak2-au/awsid).
