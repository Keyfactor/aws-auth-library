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

using Amazon;
using Amazon.Runtime.Internal.Util;
using Amazon.Runtime;
using Amazon.SecurityToken.Model;
using Amazon.SecurityToken;
using Keyfactor.Extensions.Aws.OAuth.Models;
using Keyfactor.Logging;
using Microsoft.Extensions.Logging;
using System;

using ILogger = Microsoft.Extensions.Logging.ILogger;

namespace Keyfactor.Extensions.Aws
{
    public static class AssumeRoleMethods
    {
        public static AWSCredentials AssumeRoleFromOAuth(OAuthResponse authResponse, string roleArn, RegionEndpoint region, ILogger logger)
        {
            logger.MethodEntry();
            AWSCredentials credentials = null;
            try
            {
                var stsClient = new AmazonSecurityTokenServiceClient(new AnonymousAWSCredentials(), region);
                logger.LogDebug($"Created AWS STS client with anonymous credentials in region - {region.SystemName}");
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
                logger.LogDebug($"Prepared Assume Role With Web Identity request with fields: {logAssumeRequest}");

                logger.LogTrace("Submitting Assume Role With Web Identity request.");
                var assumeResult = AsyncHelpers.RunSync(() => stsClient.AssumeRoleWithWebIdentityAsync(assumeRequest));
                logger.LogTrace("Received response to Assume Role With Web Identity request.");
                credentials = assumeResult.Credentials;
            }
            catch (Exception e)
            {
                logger.LogError($"Error Occurred in AwsAuthenticateWithWebIdentity: {e.Message}");

                throw;
            }

            return credentials;
        }

        public static AWSCredentials AssumeRole(AWSCredentials credentials, string roleArn, RegionEndpoint region, ILogger logger, string externalId = null)
        {
            logger.MethodEntry();
            logger.LogDebug($"Assuming role - {roleArn} - in region - {region.SystemName}");
            AmazonSecurityTokenServiceClient stsClient = new AmazonSecurityTokenServiceClient(credentials, region);
            logger.LogTrace("Created AWS STS client with provided AWS Credentials object.");
            return AssumeRole(stsClient, roleArn, logger, externalId);
        }

        private static AWSCredentials AssumeRole(AmazonSecurityTokenServiceClient stsClient, string roleArn, ILogger logger, string externalId = null)
        {
            logger.MethodEntry();
            AWSCredentials assumeRoleCredentials;
            try
            {
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
                    logger.LogDebug($"Prepared Assume Role request with fields: {logAssumeRequest}");
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
                    logger.LogDebug($"Prepared Assume Role request with fields: {logAssumeRequestWithExternalId}");

                }
                logger.LogTrace("Submitting Assume Role request.");
                var assumeResult = AsyncHelpers.RunSync(() => stsClient.AssumeRoleAsync(assumeRequest));
                logger.LogTrace("Received response to Assume Role request.");
                assumeRoleCredentials = assumeResult.Credentials;
            }
            catch (Exception e)
            {
                logger.LogError($"Error Occurred in AwsAuthenticate: {e.Message}");
                throw;
            }

            return assumeRoleCredentials;
        }

    }
}
