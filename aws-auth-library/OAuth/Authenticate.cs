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

using Keyfactor.Extensions.Aws.OAuth.Models;
using Keyfactor.Logging;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using RestSharp;
using System;
using System.Text;

using ILogger = Microsoft.Extensions.Logging.ILogger;

namespace Keyfactor.Extensions.Aws.OAuth
{
    public static class Authenticate
    {
        public static OAuthResponse RequestToken(OAuthParameters parameters, ILogger logger)
        {
            try
            {
                logger.MethodEntry();
                logger.LogTrace($"Creating RestClient with OAuth URL: {parameters.OAuthUrl}");

                var client = new RestClient(parameters.OAuthUrl)
                {
                    Timeout = -1
                };

                if (client.BaseUrl.Scheme != "https")
                {
                    var errorMessage = $"OAuth server needs to use HTTPS scheme but does not: {parameters.OAuthUrl}";
                    logger.LogError(errorMessage);
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
                logger.LogDebug($"Prepared Rest Request: {logHttpRequest}");

                logger.LogTrace("Executing Rest request.");
                var response = client.Execute(request);
                logger.LogTrace("Received responst to Rest request to OAUth");
                var authResponse = JsonConvert.DeserializeObject<OAuthResponse>(response.Content);
                logger.LogTrace("Deserialized OAuthResponse.");
                return authResponse;
            }
            catch (Exception e)
            {
                logger.LogError($"Error Occurred in OAuthAuthenticate: {e.Message}");
                throw;
            }
        }
    }
}
