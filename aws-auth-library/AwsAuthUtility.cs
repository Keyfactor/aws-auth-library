// Copyright 2025 Keyfactor
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
//     http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using System;
using Amazon;
using Amazon.Runtime;
using Amazon.Runtime.CredentialManagement;
using Keyfactor.Extensions.Aws.Models;
using Keyfactor.Extensions.Aws.OAuth.Models;
using Keyfactor.Logging;
using Keyfactor.Orchestrators.Extensions.Interfaces;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;

using ILogger = Microsoft.Extensions.Logging.ILogger;

namespace Keyfactor.Extensions.Aws
{
    public class AwsAuthUtility
    {
        private readonly ILogger _logger;
        private readonly IPAMSecretResolver _pam;

        public AwsAuthUtility(IPAMSecretResolver pam)
        {
            _pam = pam;
            _logger = LogHandler.GetClassLogger<AwsAuthUtility>();
        }

        public AwsExtensionCredential GetCredentials(AuthenticationParameters authParameters)
        {
            _logger.MethodEntry();

            _logger.LogDebug("Checking Client Machine field for prescence of credential [profile] value.");
            string roleArn, credentialProfile;
            if (authParameters.RoleARN.StartsWith("["))
            {
                _logger.LogTrace("Credential [profile] detected, parsing value.");
                string[] split = authParameters.RoleARN.Split(']');
                _logger.LogTrace($"Client Machine split on ']' into {split.Length} fields. 2 fields should be found.");
                _logger.LogTrace($"Found profile {split[0]} - removing '[' and ']'");
                credentialProfile = split[0].TrimStart('[').TrimEnd(']');
                roleArn = split[1];
                _logger.LogDebug($"Credential profile will be used - {credentialProfile}");
            }
            else
            {
                _logger.LogDebug("No [profile] value detected. Using Client Machine directly as Role ARN.");
                roleArn = authParameters.RoleARN;
                credentialProfile = "";
            }
            _logger.LogDebug($"AWS Role ARN - {roleArn}");
            string region = authParameters.Region;
            _logger.LogTrace($"AWS Region specified in Store Path - {region}");
            var endpoint = RegionEndpoint.GetBySystemName(region);
            _logger.LogDebug($"AWS Region Endpoint - {JsonConvert.SerializeObject(endpoint)}");

            _logger.LogDebug("Selecting credential method.");
            var fields = authParameters.CustomFields;
            CredentialMethod credentialMethod;
            if (fields.UseIAM)
            {
                credentialMethod = CredentialMethod.IamUser;
            }
            else if (fields.UseOAuth)
            {
                credentialMethod = CredentialMethod.OAuthProvider;
            }
            else if (fields.DefaultSdkAssumeRole)
            {
                if (string.IsNullOrEmpty(credentialProfile))
                {
                    credentialMethod = CredentialMethod.DefaultSdk_AssumeRole;
                }
                else
                {
                    credentialMethod = CredentialMethod.DefaultSdk_CredentialProfile_AssumeRole;
                }
            }
            else if (fields.UseDefaultSdkAuth)
            {
                if (string.IsNullOrEmpty(credentialProfile))
                {
                    credentialMethod = CredentialMethod.DefaultSdk;
                }
                else
                {
                    credentialMethod = CredentialMethod.DefaultSdk_CredentialProfile;
                }
            }
            else
            {
                // no auth method set
                var errorMsg = "No Auth method selected. This is an invalid configuration.";
                _logger.LogError(errorMsg);
                throw new Exception(errorMsg);
            }
            _logger.LogInformation($"Credential method in use for AWS Auth - {credentialMethod}");

            AWSCredentials awsCredentials;
            // TODO: use Region Endpoint for Assume Role calls
            switch (credentialMethod)
            {
                case CredentialMethod.IamUser:

                    awsCredentials = CredentialsFor_IamUser(
                        fields.IamUserAccessKey, fields.IamUserAccessSecret,
                        roleArn, region, fields.ExternalId);

                    break;

                case CredentialMethod.OAuthProvider:

                    awsCredentials = CredentialsFor_OAuthProvider(
                        fields.OAuthClientId, fields.OAuthClientSecret,
                        fields.OAuthUrl, fields.OAuthGrantType, fields.OAuthScope,
                        roleArn, region);
                    
                    break;

                case CredentialMethod.DefaultSdk_AssumeRole:

                    // get default sdk credentials first
                    AWSCredentials initialCredentials = CredentialsFor_DefaultSdk();
                    // then get final credentials via assume role with default sdk credentials
                    awsCredentials = CredentialsFor_AssumeRoleDefaultSdk(initialCredentials, roleArn, fields.ExternalId);
                    break;

                case CredentialMethod.DefaultSdk_CredentialProfile:

                    awsCredentials = CredentialsFor_CredentialProfile(credentialProfile);
                    break;

                case CredentialMethod.DefaultSdk_CredentialProfile_AssumeRole:

                    // get credentials from credential profile first
                    initialCredentials = CredentialsFor_CredentialProfile(credentialProfile);
                    // then get final credentials via assume role with credentials profile
                    awsCredentials = CredentialsFor_AssumeRoleDefaultSdk(initialCredentials, roleArn, fields.ExternalId);
                    break;

                case CredentialMethod.DefaultSdk:
                default:

                    awsCredentials = CredentialsFor_DefaultSdk();
                    break;
            }

            // store parameter values into final credential object
            var extensionCredential = new AwsExtensionCredential(credentialMethod, awsCredentials);
            extensionCredential.RoleArn = roleArn;
            extensionCredential.Region = endpoint;
            _logger.LogInformation($"AWS credential resolving completed.");
            return extensionCredential;
        }

        private AWSCredentials CredentialsFor_IamUser(string accessKey, string accessSecret, string roleArn, string region, string externalId)
        {
            _logger.MethodEntry();
            _logger.LogInformation("Using IAM User authentication method for creating AWS Credentials.");
            var resolvedAccessKey = ResolvePamField(accessKey, "IamUserAccessKey");
            var resolvedAccessSecret = ResolvePamField(accessSecret, "IamUserAccessSecret");

            _logger.LogDebug($"Assuming AWS Role with ARN - {roleArn}");

            _logger.LogTrace("Attempting to authenticate with AWS using IAM access credentials.");
            var awsCredentials = AssumeRoleMethods.AssumeRole(resolvedAccessKey, resolvedAccessSecret, roleArn, _logger, externalId);
            return awsCredentials;
        }

        private AWSCredentials CredentialsFor_OAuthProvider(string clientId, string clientSecret, string url, string grantType, string scope, string roleArn, string region)
        {
            _logger.MethodEntry();
            _logger.LogInformation("Using OAuth authentication method for creating AWS Credentials.");
            var resolvedClientId = ResolvePamField(clientId, "OAuthClientId");
            var resolvedClientSecret = ResolvePamField(clientSecret, "OAuthClientSecret");
            OAuthParameters oauthParams = new OAuthParameters()
            {
                OAuthUrl = url,
                GrantType = grantType,
                Scope = scope,
                ClientId = resolvedClientId,
                ClientSecret = resolvedClientSecret
            };

            _logger.LogTrace("Attempting to authenticate with OAuth provider.");
            OAuthResponse authResponse = OAuth.Authenticate.RequestToken(oauthParams, _logger);
            _logger.LogTrace("Received OAuth response.");

            _logger.LogDebug($"Assuming AWS Role with ARN - {roleArn}");

            _logger.LogTrace("Attempting to authenticate with AWS using OAuth response.");
            var awsCredentials = AssumeRoleMethods.AssumeRoleFromOAuth(authResponse, roleArn, _logger);
            return awsCredentials;
        }

        private AWSCredentials CredentialsFor_DefaultSdk()
        {
            _logger.MethodEntry();
            _logger.LogInformation("Using default AWS SDK credential resolution for creating AWS Credentials.");
            _logger.LogDebug($"Default Role ARN found by SDK will be used. Specified AWS Role ARN will not be used.");
            return null; // TODO: some way to create Credentials object with defaults?
        }

        private AWSCredentials CredentialsFor_CredentialProfile(string profileName)
        {
            _logger.MethodEntry();
            _logger.LogInformation("Using credential profile for creating AWS Credentials.");
            _logger.LogDebug($"Credential profile to load - {profileName}");
            var credentialProfileChain = new CredentialProfileStoreChain();

            // TODO: attempt to resolve credential profile without having to enumerate through all profiles
            var profiles = credentialProfileChain.ListProfiles();
            _logger.LogTrace($"Found {profiles.Count} profiles.");

            CredentialProfile credentialProfile = null;
            foreach(var foundProfile in profiles)
            {
                _logger.LogTrace($"Found profile: {foundProfile.Name}");
                if (string.Equals(profileName, foundProfile.Name))
                {
                    _logger.LogDebug($"Found matching credential profile with name {profileName}");
                    credentialProfile = foundProfile;
                    break;
                }
            }

            if (credentialProfile == null)
            {
                var errorMsg = "Credential profile was not loaded successfully.";
                _logger.LogError(errorMsg);
                throw new Exception(errorMsg);
            }

            _logger.LogDebug("Credential profile found. Loading credentials from profile.");
            return credentialProfile.GetAWSCredentials(credentialProfileChain);
        }

        private AWSCredentials CredentialsFor_AssumeRoleDefaultSdk(AWSCredentials originalCredentials, string roleArn, string externalId)
        {
            _logger.MethodEntry();
            // run Assume Role with existing Credentials object (from previous SDK resolution)
            _logger.LogInformation("Using default AWS SDK credential resolution with Assume Role for creating AWS Credentials.");

            _logger.LogDebug($"Assuming AWS Role with ARN - {roleArn}");

            _logger.LogTrace("Attempting to assume new Role with AWS using default AWS SDK credential.");
            var awsCredentials = AssumeRoleMethods.AssumeRole(originalCredentials, roleArn, _logger, externalId);
            return awsCredentials;
        }

        private string ResolvePamField(string field, string fieldName)
        {
            if (_pam != null)
            {
                _logger.LogDebug($"Attempting to resolve PAM-eligible field - {fieldName}");
                return _pam.Resolve(field);
            }
            else
            {
                _logger.LogTrace($"PAM-eigible field {fieldName} was not resolved via PAM as no IPAMSecretResolver was present.");
                return field;
            }
        }
    }
}