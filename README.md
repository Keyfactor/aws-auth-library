## Overview

This repository is for an AWS extension library for Keyfactor integrations. It handles authenticating with AWS in any of the various methods supported by Keyfactor Orchestrators or CA plugins.
The Nuget package of this library can be included in order to handle these AWS authentication methods. However, it requires that the specification outlined below is followed so that the fields necessary to authenticate are present.

## Compatibility

This library uses the AWS SDK version 4 for dotnet. 

## Supported Authentication Methods

A couple different methods of authentication are supported, and in some cases different options for the same method.
Unless otherwise specified, the authentication method will always perform an Assume Role call to generate temporary credentials in a specific Role context. These credentials are what are returned by the library.

### Credential inference via AWS SDK

The AWS SDK provides several methods for default credential lookup when no explicit credentials are provided.
An exhaustive list can be found here: [(AWS Documentation) Credential and profile resolution](https://docs.aws.amazon.com/sdk-for-net/v4/developer-guide/creds-assign.html)

If a specific credentials profile should be used from a shared credentials file on the system running the AWS integration, it should be specified with the Role ARN as detailed below.

By default, using the Default SDK credential inference _will not_ perform any Assume Role call, and the credential context will be preserved.
In the case that the flag `DefaultSdkAssumeRole` is set `true`, an Assume Role call will be made for the specified Role ARN. This call will be made with the credentials found by the AWS SDK, whether with a credentials [profile] or not.

### OAuth

An OAuth token is requested based on the credentials entered, with a Client Id and Client Secret supplied. This OAuth token is used to Assume Role and get temporary credentials in AWS.
The OAuth trust relationship needs to be properly configured in AWS for this to be a valid authentication option.

### IAM User

Credentials for an IAM User, in the form of an Access Key and Access Secret, are supplied. The IAM User credentials are used to Assume Role.

## Understanding the AWS Authentication Flow

The authentication workflow for AWS can be confusing, and more complex configurations require understanding of the authentication model in AWS. The following information is supplemental but not definitive for how AWS authentication works in general and when using this library.

Helpful AWS Documentation:
- [Cross-Account access with Roles](https://docs.aws.amazon.com/IAM/latest/UserGuide/tutorial_cross-account-with-roles.html)
- [Credential and profile resolution](https://docs.aws.amazon.com/sdk-for-net/v4/developer-guide/creds-assign.html)
- [Shared configuration and credentials files](https://docs.aws.amazon.com/sdkref/latest/guide/file-format.html)
- [Using a credential_process in a credential profile](https://docs.aws.amazon.com/sdkref/latest/guide/feature-process-credentials.html)
- [About IAM Roles](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html)
- [IAM Role Trust Policies](https://aws.amazon.com/blogs/security/how-to-use-trust-policies-with-iam-roles/)

### Originating and Destination accounts

In general, the auth flow starts from an Originating account and ends with a Destination account. How those entitites are specified depends on the authentication method selected.
The Destination account is the identity that will be performing all extension functions in AWS.

#### Destination Account 

The Destination account in most cases will be the Role ARN specified for authentication. In Orchestrators using the Store Type defined in the AWS-ACM-v3 Store Type, this is the value set in the Client Machine field.
Permissions and access assigned to the Destination account will be what becomes available to the extension using this library. So this entity will need permissions to access the relevant AWS systems and the specified Region.

A Trust Policy needs to be set up for any Originating -> Destination account Assume Role step. This Trust Policy should be set in the Destination account to allow the Originating account to call Assume Role.

_Basic example of Assume Role trust policy_
~~~json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "<<ORIGINATING ROLE OR ACCOUNT ARN>>"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
~~~

#### Special case: Default SDK Auth without Assume Role

When using the Default SDK Auth method, there is an additional option to perform an Assume Role call as well. If this is __not__ selected, then the Role ARN specified will __not__ be used.
In this case, the identity evaluated via Default SDK Auth will be the Destination account. This could be from EC2 instance credentials, a credential profile, or other options provided by the SDK.

If Default SDK Auth should be used to establish _initial_ identity, but then used as an Originating account to access a Destination account, the Default SDK Assume Role flag should be set so that the Role Arn specified will be used via an Assume Role call.

#### Originating Account

The Originating account acts as the initial authentication method to AWS, and is specified based on the auth configuration passed into this Auth library.
This should be thought of as the credentials or account that are the input to the Keyfactor extension (and thus this library).
Each of the auth methods determines the Originating in a different manner.

##### Default SDK Originating Account

The Originating Account for the Default SDK method will be the identity resolved by the SDK. See the linked AWS documentation on "Credential and profile resolution" to see how this works.

If a `[profile]` is specified with the Role ARN, then the `[profile]` will be given priority over any other SDK evaluation method.

The identity found by the SDK is used as an Originating Account when the Default SDK Assume Role flag is set. This method is used for loading EC2 instance credentials.

##### IAM User Originating Account

If IAM User authentication is selected, an Access Key and Access Secret are entered and used as Basic AWS Credentials.
The IAM User associated with those credentials will be the Originating account, and will be used to make an Assume Role call to the specified Role ARN (the Destination account).

##### OAuth Originating Account

When OAuth is selected, the configuration for OAuth is used to get a token. A trust relationship with the OAuth provider is configured as an Identity Provider in AWS beforehand.

The ARN generated for the OIDC IdP for the OAuth provider is the resultant Originating account.
When that ARN is used to Assume Role for the Role ARN specified, a trust relationship needs to be configured correctly for the Destination Role ARN.

This means the trust relationship when using OAuth is slightly different than the example for Assume Role provided above.

_Example of Assume Role trust policy for OAuth_

~~~json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Federated": "<<GENERATED OIDC IDP ARN FOR OAUTH PROVIDER>>"
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    "<<IDP NAME>>:aud": "<<CLIENT ID A.K.A. AUDIENCE>>"
                }
            }
        }
    ]
}
~~~

## Technical Considerations

Some supported authentication methods have some considerations that should be taken into account when deploying using that method.

### Default SDK Auth

Several settings for auth with the SDK can be configured via enviroment variables. Those features are preserved in this library. However, there is no direct interaction with those environment variables.
Thus, the SDK evaluation method needs to be understood and the environment variables set correctly so that they adhere to the AWS SDK documentation linked above.

### OAuth

The current implementation of requesting an OAuth token submits the Client Id and Client Secret as a Basic Authorization header.
OAuth providers will need to be configured to accept and authenticate the Basic auth header as opposed to expecting this in the POST body.

## Specification

The following specification is split into two sections:
- plain text inputs, which in Certificate Stores are supplied in the required fields `Client Machine` and `Store Path`
- object specification, which is implemented via Custom Fields

### Required text inputs

__Role ARN__

The `Client Machine` field for Certificate Stores supplies the Role ARN for authentication. Otherwise this should be provided by a text field.
The Role ARN can take two forms, but will always indicate a specific Role under an AWS Account ID:
- `arn:aws:iam::<<AWS ACCOUNT ID>>:role/<<ROLE NAME>>`
    - in some cases, portions of the ARN may differ from above when targeting special AWS environments
- `[<<CREDENTIAL PROFILE NAME>>]arn:aws:iam::<<AWS ACCOUNT ID>>:role/<<ROLE NAME>>`
    - this special case allows for a `[profile]` name to supplied for authentication
    - this profile will only be used when doing Default SDK auth

__Region__

The `Store Path` field for Certificate Stores supplies the Region for authentication. This region will be used for any requests to Assume Role or generate an STS Token.
Only a single region can be specified in this field.

### Authentication Input Object Specification

The following fields must be implented and supplied to support all possible AWS authentication options. If the exact names are not used, and the object cannot be directly deserialized from inputs to the integration, the necessary properties should be correctly set on the Parameters object.

| Field Name | Type | Value |
| - | - | - |
| UseDefaultSdkAuth | boolean | Set `true` if the AWS SDK should be used for authentication. This supports EC2 credential profiles. If a `[profile]` is set in the Role ARN, that credential profile will be used. |
| DefaultSdkAssumeRole | boolean | If `UseDefaultSdkAuth` is `true`, setting this field to `true` will perform Assume Role with the credentials found by the AWS SDK. |
| UseOAuth | boolean | Set `true` if OAuth should be used to perform initial authentication, which will then assume the specified Role ARN. |
| OAuthScope | string | The OAuth scope to request. |
| OAuthGrantType | string | The OAuth grant type to request. |
| OAuthUrl | string | The OAuth token endpoint to submit the request to. |
| OAuthClientId | secret string | The OAuth Client Id. |
| OAuthClientSecret | secret string | The OAuth Client Secret. |
| UseIAM | boolean | Set `true` if IAM User credentials should be used to Assume Role. |
| IAMUserAccessKey | secret string | The IAM User Access Key. |
| IAMUserAccessSecret | secret string | The IAM User Access Secret. |
| ExternalId | string | Sets `sts:ExternalId` on Assume Role requests. |
