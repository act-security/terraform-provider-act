# Changelog

## [0.3.2](https://github.com/act-security/terraform-provider-act/compare/v0.3.1...v0.3.2) (2026-11-19)


### Bug Fixes

* publish the ~&gt; 0.3 version constraint in the registry docs ([#23](https://github.com/act-security/terraform-provider-act/issues/23)) ([896d8cf](https://github.com/act-security/terraform-provider-act/commit/896d8cfc282f304c09a30661de8d93fd6d8b5f5e))

## [0.3.1](https://github.com/act-security/terraform-provider-act/compare/v0.3.0...v0.3.1) (2026-11-18)


### Features

* add Azure deployment, onboarding and log source support ([#20](https://github.com/act-security/terraform-provider-act/issues/20)) ([4c7ffa3](https://github.com/act-security/terraform-provider-act/commit/4c7ffa3aff4946480a41c7724b905dd9583cafbd))

## [0.3.0](https://github.com/act-security/terraform-provider-act/compare/v0.2.1...v0.3.0) (2026-11-16)


### Features

* answer 501 from the fake for operations it lacks and publish api/support.json ([#14](https://github.com/act-security/terraform-provider-act/issues/14)) ([cc484ef](https://github.com/act-security/terraform-provider-act/commit/cc484ef26018a36f6e5dbd0db89e6a20a890734a))
* manage AWS account and organization deployments ([#10](https://github.com/act-security/terraform-provider-act/issues/10)) ([ce27342](https://github.com/act-security/terraform-provider-act/commit/ce273424d17e984df8efb289f387c9a88c019131))
* manage notification rules and recipients ([#7](https://github.com/act-security/terraform-provider-act/issues/7)) ([de68318](https://github.com/act-security/terraform-provider-act/commit/de683183d4e24c48ea9f3f5f8d407231f190ebfa))
* warn at plan and refuse the apply when the API key cannot write the change ([#16](https://github.com/act-security/terraform-provider-act/issues/16)) ([eaf0cc7](https://github.com/act-security/terraform-provider-act/commit/eaf0cc750fc5fd62f4f4fcb78dcdb28092b5cf2d))


### Bug Fixes

* accept the CloudTrail logs and AI services capabilities on AWS deployments ([#19](https://github.com/act-security/terraform-provider-act/issues/19)) ([cabca92](https://github.com/act-security/terraform-provider-act/commit/cabca927d316e36567f868dc32017ca96f1dccfc))
* force replacement when deployment_method changes ([#15](https://github.com/act-security/terraform-provider-act/issues/15)) ([02c6c00](https://github.com/act-security/terraform-provider-act/commit/02c6c0087ab35d966f31283d2bcdd002e46f6539))
* honour X-Retry-After when a 429 has no Retry-After ([#13](https://github.com/act-security/terraform-provider-act/issues/13)) ([ababe44](https://github.com/act-security/terraform-provider-act/commit/ababe444f0345f359fc110f01b85f4f8c2b23d3a))
* let a deterministic verification failure settle before giving up ([#12](https://github.com/act-security/terraform-provider-act/issues/12)) ([4e88b51](https://github.com/act-security/terraform-provider-act/commit/4e88b510f2a76566d96096f7753fc35e2c012637))


### Documentation

* prepare the 0.3.0 release of the AWS deployment resources ([#18](https://github.com/act-security/terraform-provider-act/issues/18)) ([db27688](https://github.com/act-security/terraform-provider-act/commit/db27688fc7f4e70ca19595a05d69170a5c41b638))

## [0.2.1](https://github.com/act-security/terraform-provider-act/compare/v0.2.0...v0.2.1) (2026-11-11)


### Features

* manage Slack, Jira, Wiz and Splunk integrations ([#6](https://github.com/act-security/terraform-provider-act/issues/6)) ([b0aa109](https://github.com/act-security/terraform-provider-act/commit/b0aa109371db0f562c435b69d932f3b6334a24e3))


### Bug Fixes

* build with Go 1.26.11 and golang.org/x/net 0.62.0 ([#9](https://github.com/act-security/terraform-provider-act/issues/9)) ([07931d8](https://github.com/act-security/terraform-provider-act/commit/07931d87bc660b760c5d33269c6d7f6b934141fa))

## [0.2.0](https://github.com/act-security/terraform-provider-act/compare/v0.1.0...v0.2.0) (2026-11-09)


### ⚠ BREAKING CHANGES

* remove the region provider argument ([#2](https://github.com/act-security/terraform-provider-act/issues/2))

### Features

* remove the region provider argument ([#2](https://github.com/act-security/terraform-provider-act/issues/2)) ([be71758](https://github.com/act-security/terraform-provider-act/commit/be71758930c9520798b4ebe62517587f8700eb55))

## 0.1.0 (2026-11-09)


### Features

* initial release ([11efcbd](https://github.com/act-security/terraform-provider-act/commit/11efcbd5aa5de47b84f2d580bbe61690fa31e5e3))
