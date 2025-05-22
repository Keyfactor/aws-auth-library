using Amazon;
using Amazon.SecurityToken.Model;
using System;

namespace Keyfactor.Extensions.Aws
{
    public class AwsExtensionCredential
    {
        private Credentials _awsCredentials;
        internal string CredentialProfile { get; set; }
        public CredentialMethod CredentialMethod { get; set; }
        public string RoleArn { get; set; }

        public RegionEndpoint Region { get; set; }

        public AwsExtensionCredential(CredentialMethod method, Credentials awsCredentials, string credentialProfile = null)
        {
            _awsCredentials = awsCredentials;
            CredentialMethod = method;
            CredentialProfile = credentialProfile;
        }

        private void LogCredentialInformation()
        {

        }

        public Credentials GetAwsCredentialObject()
        {
            return _awsCredentials;
        }
    }
}
