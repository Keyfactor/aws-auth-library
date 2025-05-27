using Amazon.Runtime.Internal.Util;
using Amazon.Runtime;
using Amazon.SecurityToken.Model;
using Amazon.SecurityToken;
using Keyfactor.Extensions.Aws.OAuth.Models;
using Keyfactor.Logging;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Text;

using ILogger = Microsoft.Extensions.Logging.ILogger;

namespace Keyfactor.Extensions.Aws
{
    public static class AssumeRoleMethods
    {
        public static AWSCredentials AssumeRoleFromOAuth(OAuthResponse authResponse, string roleArn, ILogger logger)
        {
            logger.MethodEntry();
            AWSCredentials credentials = null;
            try
            {
                // TODO: make region specific
                var stsClient = new AmazonSecurityTokenServiceClient(new AnonymousAWSCredentials());
                logger.LogTrace("Created AWS STS client with anonymous credentials.");
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

        public static AWSCredentials AssumeRole(string accessKey, string accessSecret, string roleArn, ILogger logger, string externalId = null)
        {
            logger.MethodEntry();

            // TODO: make region specific
            if (accessKey != null && accessSecret != null)
            {
                AmazonSecurityTokenServiceClient stsClient = new AmazonSecurityTokenServiceClient(accessKey, accessSecret);
                logger.LogTrace("Created AWS STS client with IAM user credentials.");
                return AssumeRole(stsClient, roleArn, logger, externalId);
            }
            else
            {
                // TODO: needs to load with Credential Profile in mind
                AmazonSecurityTokenServiceClient stsClient = new AmazonSecurityTokenServiceClient();
                logger.LogTrace("Created AWS STS client with default credential resolution.");
                return AssumeRole(stsClient, roleArn, logger, externalId);
            }
        }

        public static AWSCredentials AssumeRole(AWSCredentials credentials, string roleArn, ILogger logger, string externalId = null)
        {
            logger.MethodEntry();
            // TODO: make region specific
            AmazonSecurityTokenServiceClient stsClient = new AmazonSecurityTokenServiceClient(credentials);

            return AssumeRole(stsClient, roleArn, logger, externalId);
        }

        private static AWSCredentials AssumeRole(AmazonSecurityTokenServiceClient stsClient, string roleArn, ILogger logger, string externalId = null)
        {
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
