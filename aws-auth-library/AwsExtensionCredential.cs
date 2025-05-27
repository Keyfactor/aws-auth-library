using Amazon;
using Amazon.Runtime;
using Amazon.SecurityToken.Model;
using System;

namespace Keyfactor.Extensions.Aws
{
    public class AwsExtensionCredential
    {
        private AWSCredentials _awsCredentials;
        internal string CredentialProfile { get; set; }
        public CredentialMethod CredentialMethod { get; set; }
        public string RoleArn { get; set; }

        public RegionEndpoint Region { get; set; }

        public AwsExtensionCredential(CredentialMethod method, AWSCredentials awsCredentials, string credentialProfile = null)
        {
            _awsCredentials = awsCredentials;
            CredentialMethod = method;
            CredentialProfile = credentialProfile;
        }

        private void LogCredentialInformation()
        {

        }

        public AWSCredentials GetAwsCredentialObject()
        {
            return _awsCredentials;
        }
    }
}
