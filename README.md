# Assume Role ID

RaaS (Roles as a Service) hosted at [https://id.assume.ryanjarv.sh](https://id.assume.ryanjarv.sh) to help you switch away from IAM Users, or for research, or maybe honeypots, whatever you can think of tbh. Anyway, it generates world assumable roles and then poll's CloudTrail for `sts:AssumeRole` API calls to assume them. The service also returns API Actions called on each session, however the frontend doesn't display this yet.


## Bugs

Ideally you shouldn't be able to view events for roles you didn't generate, however don't rely on this right now. I'll have to fix the issue of stealing roles when you know the name first.

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
