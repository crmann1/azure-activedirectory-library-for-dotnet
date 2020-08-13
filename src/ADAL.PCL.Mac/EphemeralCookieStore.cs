//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

using System;
using System.Net;
using System.Collections.Generic;
using System.Linq;
using Foundation;
using WebKit;

namespace Microsoft.IdentityService.Clients.ActiveDirectory
{
    class EphemeralCookieStore
    {
        readonly CookieContainer container = new CookieContainer();

        /// <summary>
        /// Captures cookies that were set by JavaScript.
        /// </summary>
        public void TakeCookies(WebView webView)
        {
            var docCookiesNSString = webView.WindowScriptObject.EvaluateWebScript("document.cookie") as NSString;
            if (docCookiesNSString == null)
            {
                return;
            }

            var docUrlNSString = webView.WindowScriptObject.EvaluateWebScript("document.URL") as NSString;

            var docCookies = docCookiesNSString.ToString();
            var docUrl = new Uri(docUrlNSString.ToString());

            foreach (var cookieStr in docCookies.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries))
            {
                var eqIdx = cookieStr.IndexOf('=');
                var name = cookieStr.Substring(0, eqIdx).Trim();
                var value = cookieStr.Substring(eqIdx + 1).Trim();
                var isSecure = string.Equals("https", docUrl.Scheme, StringComparison.OrdinalIgnoreCase);

                // NOTE:
                // we don't have any way to get info such as domain, expiry etc from the document
                // so make a best guess. It shouldn't really matter since the cookies are only kept
                // alive as long as the sign-in window is open
                //
                var cookie = new NSHttpCookie(new NSMutableDictionary {
                    { NSHttpCookie.KeyName, new NSString (name) },
                    { NSHttpCookie.KeyValue, new NSString (value) },
                    { NSHttpCookie.KeyDomain, new NSString (docUrl.Host) },
                    { NSHttpCookie.KeyPath, new NSString ("/") },
                    { NSHttpCookie.KeySecure, NSNumber.FromBoolean (isSecure) },
                });

                try
                {
                    AddCookieToStorage(cookie);
                }
                catch (Exception ex)
                {
                    PlatformPlugin.Logger.Warning(null, string.Format("Invalid cookie for web view url: {0} document.cookies: {1}", docUrl, docCookies));
                    PlatformPlugin.Logger.Error(null, ex);
                }
            }
        }

        public void TakeCookies(NSUrlResponse response)
        {
            var httpResponse = response as NSHttpUrlResponse;
            if (httpResponse == null)
                return;

            var cookies = NSHttpCookie.CookiesWithResponseHeaderFields(httpResponse.AllHeaderFields, httpResponse.Url);
            foreach (var cookie in cookies)
            {
                try
                {
                    AddCookieToStorage(cookie);
                }
                catch (Exception ex)
                {
                    PlatformPlugin.Logger.Warning(null, string.Format("Invalid cookie for response url: {0}", httpResponse.Url));
                    PlatformPlugin.Logger.Error(null, ex);
                }
            }
        }

        public void GiveCookies(NSMutableUrlRequest request)
        {
            request.ShouldHandleCookies = false;
            var cookies = GetStoredCookiesForUrl(request.Url).ToArray();
            var headers = NSHttpCookie.RequestHeaderFieldsWithCookies(cookies);
            var mutableHeaders = (NSMutableDictionary)request.Headers.MutableCopy();
            mutableHeaders.SetValuesForKeysWithDictionary(headers);
            request.Headers = mutableHeaders;
        }

        void AddCookieToStorage(NSHttpCookie cookie)
        {
            container.Add(new Cookie(cookie.Name, cookie.Value, cookie.Path, cookie.Domain));
        }

        IEnumerable<NSHttpCookie> GetStoredCookiesForUrl(NSUrl url)
        {
            var collection = container.GetCookies(url);

			foreach (Cookie cookie in collection) {
                yield return new NSHttpCookie(cookie);
            }
        }
    }
}