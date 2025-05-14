using Amazon.Runtime;
using System;
using System.Collections.Generic;
using System.Text;

namespace aws_auth_library
{
    public static class AwsClientCreator
    {
        public static T CreateAwsClientWithCredentials<T>(AwsExtensionCredential credential)
            where T : AmazonServiceClient
        {
            // assumes specific type of AwsServiceClient has a constructor with RegionEndpoint arg
            // create AwsServiceClient object of the specific client type
            // TODO: handle NULL credential (probably not here)
            T awsServiceClient = (T)Activator.CreateInstance(typeof(T), credential.GetAwsCredentialObject(), credential.Region);
            return awsServiceClient;
        }

        public static T CreateAwsClientWithCredentials<T,U>(AwsExtensionCredential credential)
            where T: AmazonServiceClient
            where U: ClientConfig
        {
            // create ClientConfig object of the specific client type
            U clientConfig = (U)Activator.CreateInstance(typeof(U));
            // set RegionEndpoint for the ClientConfig
            clientConfig.RegionEndpoint = credential.Region;

            // create AwsServiceClient object of the specific client type
            // TODO: handle NULL credential (probably not here)
            T awsServiceClient = (T)Activator.CreateInstance(typeof(T), credential.GetAwsCredentialObject(), clientConfig);
            return awsServiceClient;
        }
    }
}
