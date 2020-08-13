//
// MacProxyCredentialsProvider.cs
//
// Author:
//       Bojan Rajkovic <bojan.rajkovic@xamarin.com>
//
// Copyright (c) 2013 Xamarin Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

using System;
using System.Net;

namespace Microsoft.IdentityService.Clients.ActiveDirectory
{
    static class MacProxyCredentialProvider
    {
        public static ICredentials GetCredentials(Uri uri, IWebProxy proxy)
        {
            // if looking for proxy credentials, we care about the proxy's URL, not the request URL
            var proxyUri = proxy.GetProxy(uri);
            if (proxyUri != null)
                uri = proxyUri;

            return GetSystemProxyCredentials(uri);
        }

        static ICredentials GetSystemProxyCredentials(Uri uri)
        {
            var kind = SecProtocolType.Any;
            if (uri.Scheme == "http")
                kind = SecProtocolType.HTTPProxy;
            else if (uri.Scheme == "https")
                kind = SecProtocolType.HTTPSProxy;

            var existing = Keychain.FindInternetUserNameAndPassword(uri, kind);
            if (existing != null && existing.Item1 != null && existing.Item2 != null)
                return new NetworkCredential(existing.Item1, existing.Item2);

            return null;
        }
    }
}
