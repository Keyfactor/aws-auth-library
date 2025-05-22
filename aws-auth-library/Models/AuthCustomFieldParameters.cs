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


using Newtonsoft.Json;
using System.ComponentModel;

namespace Keyfactor.Extensions.Aws.Models
{
    public class AuthCustomFieldParameters
    {
        [JsonProperty("UseDefaultSdkAuth")]
        [DefaultValue(false)]
        public bool UseDefaultSdkAuth { get; set; }

        [JsonProperty("DefaultSdkAssumeRole")]
        [DefaultValue(false)]
        public bool DefaultSdkAssumeRole { get; set; }

        [JsonProperty("UseOAuth")]
        [DefaultValue(false)]
        public bool UseOAuth { get; set; }

        [JsonProperty("OAuthScope")]
        public string OAuthScope { get; set; }

        [JsonProperty("OAuthGrantType")]
        public string OAuthGrantType { get; set; }

        [JsonProperty("OAuthUrl")]
        public string OAuthUrl { get; set; }

        [JsonProperty("OAuthClientId")]
        public string OAuthClientId { get; set; }

        [JsonProperty("OAuthClientSecret")]
        public string OAuthClientSecret { get; set; }

        [JsonProperty("UseIAM")]
        [DefaultValue(false)]
        public bool UseIAM { get; set; }

        [JsonProperty("IAMUserAccessKey")]
        public string IamUserAccessKey { get; set; }

        [JsonProperty("IAMUserAccessSecret")]
        public string IamUserAccessSecret { get; set; }

        [JsonProperty("ExternalId")]
        public string ExternalId { get; set; }
    }
}
