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
using System.Net;
using System.Text;
using Amazon;
using Amazon.Runtime;
using Amazon.Runtime.Internal.Util;
using Amazon.SecurityToken;
using Amazon.SecurityToken.Model;
using Keyfactor.Extensions.Aws.Models;
using Keyfactor.Extensions.Aws.OAuth.Models;
using Keyfactor.Logging;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.Extensions.Interfaces;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using RestSharp;

using ILogger = Microsoft.Extensions.Logging.ILogger;

namespace Keyfactor.Extensions.Aws
{
    public class AwsAuthUtility
    {
        private readonly ILogger _logger;
        private readonly IPAMSecretResolver _pam;

        public AwsAuthUtility(IPAMSecretResolver pam, ILogger logger)
        {
            _pam = pam;
            _logger = logger;
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
            var customFields = authParameters.CustomFields;
            CredentialMethod credentialMethod;
            if (customFields.UseIAM)
            {
                credentialMethod = CredentialMethod.IamUser;
            }
            else if (customFields.UseOAuth)
            {
                credentialMethod = CredentialMethod.OAuthProvider;
            }
            else if (customFields.DefaultSdkAssumeRole)
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
            else if (customFields.UseDefaultSdkAuth)
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
                throw new Exception("No Auth method selected. This is an invalid configuration.");
            }
            _logger.LogInformation($"Credential method in use for AWS Auth - {credentialMethod}");

            AwsExtensionCredential extensionCredential;
            // TODO: rename methods to Assume Role
            // TODO: use Region Endpoint for Assume Role calls
            switch (credentialMethod)
            {
                case CredentialMethod.IamUser:
                    _logger.LogInformation("Using IAM User authentication method for creating AWS Credentials.");
                    var accessKey = ResolvePamField(customFields.IamUserAccessKey, "IamUserAccessKey");
                    var accessSecret = ResolvePamField(customFields.IamUserAccessSecret, "IamUserAccessSecret");

                    _logger.LogDebug($"Assuming AWS Role with ARN - {roleArn}");

                    _logger.LogTrace("Attempting to authenticate with AWS using IAM access credentials.");
                    var awsCredentials = AwsAuthenticate(accessKey, accessSecret, roleArn, customFields.ExternalId);
                    extensionCredential = new AwsExtensionCredential(credentialMethod, awsCredentials);
                    break;
                case CredentialMethod.OAuthProvider:
                    _logger.LogInformation("Using OAuth authentication method for creating AWS Credentials.");
                    var clientId = ResolvePamField(customFields.OAuthClientId, "OAuthClientId");
                    var clientSecret = ResolvePamField(customFields.OAuthClientSecret, "OAuthClientSecret");
                    OAuthParameters oauthParams = new OAuthParameters()
                    {
                        OAuthUrl = customFields.OAuthUrl,
                        GrantType = customFields.OAuthGrantType,
                        Scope = customFields.OAuthScope,
                        ClientId = clientId,
                        ClientSecret = clientSecret
                    };

                    _logger.LogTrace("Attempting to authenticate with OAuth provider.");
                    OAuthResponse authResponse = OAuthAuthenticate(oauthParams);
                    _logger.LogTrace("Received OAuth response.");

                    _logger.LogDebug($"Assuming AWS Role with ARN - {roleArn}");

                    _logger.LogTrace("Attempting to authenticate with AWS using OAuth response.");
                    awsCredentials = AwsAuthenticateWithWebIdentity(authResponse, roleArn);
                    extensionCredential = new AwsExtensionCredential(credentialMethod, awsCredentials);
                    break;
                case CredentialMethod.DefaultSdk_AssumeRole:
                    // use SDK credential resolution, but run Assume Role
                    _logger.LogInformation("Using default AWS SDK credential resolution with Assume Role for creating AWS Credentials.");

                    _logger.LogDebug($"Assuming AWS Role with ARN - {roleArn}");

                    _logger.LogTrace("Attempting to assume new Role with AWS using default AWS SDK credential.");
                    awsCredentials = AwsAuthenticate(null, null, roleArn, customFields.ExternalId);
                    extensionCredential = new AwsExtensionCredential(credentialMethod, awsCredentials);
                    break;
                // TODO: add case for where Profile is specified
                case CredentialMethod.DefaultSdk:
                default:
                    _logger.LogInformation("Using default AWS SDK credential resolution for creating AWS Credentials.");
                    // TODO: update logging message
                    _logger.LogDebug($"Default Role and Account ID will be used. Specified AWS Role ARN - {roleArn} - will not be used.");
                    extensionCredential = new AwsExtensionCredential(credentialMethod, null);
                    break;
            }

            // TODO: add logging
            // store parameter values into final credential object
            extensionCredential.RoleArn = roleArn;
            extensionCredential.Region = endpoint;
            return extensionCredential;
        }

        public Credentials AwsAuthenticateWithWebIdentity(OAuthResponse authResponse, string roleArn)
        {
            _logger.MethodEntry();
            Credentials credentials = null;
            try
            {
                // TODO: make region specific
                var stsClient = new AmazonSecurityTokenServiceClient(new AnonymousAWSCredentials());
                _logger.LogTrace("Created AWS STS client with anonymous credentials.");
                var assumeRequest = new AssumeRoleWithWebIdentityRequest
                {
                    WebIdentityToken = authResponse?.AccessToken,
                    RoleArn = roleArn,
                    RoleSessionName = "KeyfactorSession",
                    DurationSeconds = Convert.ToInt32(authResponse?.ExpiresIn)
                };
                var logAssumeRequest = new
                {
                    WebIdentityToken = "**redacted**",
                    assumeRequest.RoleArn,
                    assumeRequest.RoleSessionName,
                    assumeRequest.DurationSeconds
                };
                _logger.LogDebug($"Prepared Assume Role With Web Identity request with fields: {logAssumeRequest}");

                _logger.LogTrace("Submitting Assume Role With Web Identity request.");
                var assumeResult = AsyncHelpers.RunSync(() => stsClient.AssumeRoleWithWebIdentityAsync(assumeRequest));
                _logger.LogTrace("Received response to Assume Role With Web Identity request.");
                credentials = assumeResult.Credentials;
            }
            catch (Exception e)
            {
                _logger.LogError($"Error Occurred in AwsAuthenticateWithWebIdentity: {e.Message}");

                throw;
            }

            return credentials;
        }

        public Credentials AwsAuthenticate(string accessKey, string accessSecret, string roleArn, string externalId = null)
        {
            _logger.MethodEntry();
            Credentials credentials = null;
            try
            {
                // TODO: make region specific
                AmazonSecurityTokenServiceClient stsClient;
                if (accessKey != null && accessSecret != null)
                {
                    stsClient = new AmazonSecurityTokenServiceClient(accessKey, accessSecret);
                    _logger.LogTrace("Created AWS STS client with IAM user credentials.");
                }
                else
                {
                    // TODO: needs to load with Credential Profile in mind
                    stsClient = new AmazonSecurityTokenServiceClient();
                    _logger.LogTrace("Created AWS STS client with default credential resolution.");
                }

                var assumeRequest = new AssumeRoleRequest
                {
                    RoleArn = roleArn,
                    RoleSessionName = "KeyfactorSession",
                };

                if (string.IsNullOrWhiteSpace(externalId))
                {
                    // no sts:ExternalId
                    var logAssumeRequest = new
                    {
                        assumeRequest.RoleArn,
                        assumeRequest.RoleSessionName
                    };
                    _logger.LogDebug($"Prepared Assume Role request with fields: {logAssumeRequest}");
                }
                else
                {
                    // include sts:ExternalId with assume role request
                    assumeRequest.ExternalId = externalId;
                    var logAssumeRequestWithExternalId = new
                    {
                        assumeRequest.RoleArn,
                        assumeRequest.RoleSessionName,
                        assumeRequest.ExternalId
                    };
                    _logger.LogDebug($"Prepared Assume Role request with fields: {logAssumeRequestWithExternalId}");

                }
                _logger.LogTrace("Submitting Assume Role request.");
                var assumeResult = AsyncHelpers.RunSync(() => stsClient.AssumeRoleAsync(assumeRequest));
                _logger.LogTrace("Received response to Assume Role request.");
                credentials = assumeResult.Credentials;
            }
            catch (Exception e)
            {
                _logger.LogError($"Error Occurred in AwsAuthenticate: {e.Message}");
                throw;
            }

            return credentials;
        }

        public OAuthResponse OAuthAuthenticate(OAuthParameters parameters)
        {
            try
            {
                _logger.MethodEntry();
                _logger.LogTrace($"Creating RestClient with OAuth URL: {parameters.OAuthUrl}");

                var client = new RestClient(parameters.OAuthUrl)
                {
                    Timeout = -1
                };

                if (client.BaseUrl.Scheme != "https")
                {
                    var errorMessage = $"OAuth server needs to use HTTPS scheme but does not: {parameters.OAuthUrl}";
                    _logger.LogError(errorMessage);
                    throw new Exception(errorMessage);
                }

                var request = new RestRequest(Method.POST);
                request.AddHeader("Accept", "application/json");
                var clientId = parameters.ClientId;
                var clientSecret = parameters.ClientSecret;
                var plainTextBytes = Encoding.UTF8.GetBytes($"{clientId}:{clientSecret}");
                var authHeader = Convert.ToBase64String(plainTextBytes);
                request.AddHeader("Authorization", $"Basic {authHeader}");
                request.AddHeader("Content-Type", "application/x-www-form-urlencoded");
                request.AddParameter("grant_type", parameters.GrantType);
                request.AddParameter("scope", parameters.Scope);

                var logHttpRequest = new
                {
                    Method = "POST",
                    AcceptHeader = "application/json",
                    AuthorizationHeader = "Basic **redacted**",
                    ContentTypeHeader = "application/x-www-form-urlencoded",
                    grant_type = parameters.GrantType,
                    scope = parameters.Scope
                };
                _logger.LogDebug($"Prepared Rest Request: {logHttpRequest}");

                _logger.LogTrace("Executing Rest request.");
                var response = client.Execute(request);
                _logger.LogTrace("Received responst to Rest request to OAUth");
                var authResponse = JsonConvert.DeserializeObject<OAuthResponse>(response.Content);
                _logger.LogTrace("Deserialized OAuthResponse.");
                return authResponse;
            }
            catch (Exception e)
            {
                _logger.LogError($"Error Occurred in OAuthAuthenticate: {e.Message}");
                throw;
            }
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