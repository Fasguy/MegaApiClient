﻿using System.Collections.Generic;
using System.Linq;

namespace CG.Web.MegaApiClient
{
  using System;
  using System.IO;
  using System.Net;
  using System.Reflection;
  using System.Text;
  using System.Threading;
  using System.Net.Http;
  using System.Net.Http.Headers;

  public class WebClient : IWebClient
  {
    private const int DefaultResponseTimeout = Timeout.Infinite;

    private static readonly HttpClient s_sharedHttpClient = CreateHttpClient(DefaultResponseTimeout, GenerateUserAgent());

    private readonly HttpClient _httpClient;

    public WebClient(int responseTimeout = DefaultResponseTimeout, ProductInfoHeaderValue userAgent = null)
    {
      if (responseTimeout == DefaultResponseTimeout && userAgent == null)
      {
        _httpClient = s_sharedHttpClient;
      }
      else
      {
        _httpClient = CreateHttpClient(responseTimeout, userAgent ?? GenerateUserAgent());
      }
    }

    public int BufferSize { get; set; } = Options.DefaultBufferSize;

    public string PostRequestJson(Uri url, string jsonData)
    {
      using (var jsonStream = new MemoryStream(jsonData.ToBytes()))
      {
        using (var responseStream = PostRequest(url, jsonStream, "application/json"))
        {
          return StreamToString(responseStream);
        }
      }
    }

    public string PostRequestRaw(Uri url, Stream dataStream)
    {
      using (var responseStream = PostRequest(url, dataStream, "application/json"))
      {
        return StreamToString(responseStream);
      }
    }

    public Stream PostRequestRawAsStream(Uri url, Stream dataStream)
    {
      return PostRequest(url, dataStream, "application/octet-stream");
    }

    public Stream GetRequestRaw(Uri url)
    {
      return _httpClient.GetStreamAsync(url).Result;
    }

    private Stream PostRequest(Uri url, Stream dataStream, string contentType)
    {
      using (var content = new StreamContent(dataStream, BufferSize))
      {
        content.Headers.ContentType = new MediaTypeHeaderValue(contentType);

        var requestMessage = new HttpRequestMessage(HttpMethod.Post, url)
        {
          Content = content
        };

        var response = _httpClient.SendAsync(requestMessage, HttpCompletionOption.ResponseHeadersRead).Result;
        if (RequestFailed(response, out var stream))
        {
          return stream;
        }

        if (response.Headers.TryGetValues("X-Hashcash", out var values))
        {
          var value = values.First();
          var output = Hashcash.GenerateToken(value);
          
          content.Headers.Add("X-Hashcash", output);

          requestMessage = new HttpRequestMessage(HttpMethod.Post, url)
          {
            Content = content
          };
          response = _httpClient.SendAsync(requestMessage, HttpCompletionOption.ResponseHeadersRead).Result;
          if (RequestFailed(response, out stream))
          {
            return stream;
          }
        }

        response.EnsureSuccessStatusCode();

        return response.Content.ReadAsStreamAsync().Result;
      }

      bool RequestFailed(HttpResponseMessage response, out Stream stream)
      {
        if (!response.IsSuccessStatusCode
            && response.StatusCode == HttpStatusCode.InternalServerError
            && response.ReasonPhrase == "Server Too Busy")
        {
          stream = new MemoryStream(Encoding.UTF8.GetBytes(((long)ApiResultCode.RequestFailedRetry).ToString()));
          return true;
        }

        stream = null;
        return false;
      }
    }

    private string StreamToString(Stream stream)
    {
      using (var streamReader = new StreamReader(stream, Encoding.UTF8))
      {
        return streamReader.ReadToEnd();
      }
    }

    private static HttpClient CreateHttpClient(int timeout, ProductInfoHeaderValue userAgent)
    {
      var httpClient = new HttpClient(new HttpClientHandler { AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate });

      httpClient.Timeout = TimeSpan.FromMilliseconds(timeout);
      httpClient.DefaultRequestHeaders.UserAgent.Add(userAgent);

      return httpClient;
    }

    private static ProductInfoHeaderValue GenerateUserAgent()
    {
      var assemblyName = typeof(WebClient).GetTypeInfo().Assembly.GetName();
      return new ProductInfoHeaderValue(assemblyName.Name, assemblyName.Version.ToString(2));
    }
  }
}
