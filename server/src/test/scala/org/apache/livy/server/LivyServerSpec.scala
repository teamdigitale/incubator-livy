package org.apache.livy.server

import java.util.concurrent.TimeUnit

import org.apache.commons.httpclient.HttpClient
import org.apache.http.HttpResponse
import org.apache.http.auth.{ AuthScope, BasicUserPrincipal, Credentials, UsernamePasswordCredentials }
import org.apache.http.client.config.RequestConfig
import org.apache.http.client.methods.{ HttpGet, HttpUriRequest }
import org.apache.http.impl.NoConnectionReuseStrategy
import org.apache.http.impl.client.{ BasicCredentialsProvider, CloseableHttpClient, HttpClientBuilder }
import org.apache.http.impl.conn.BasicHttpClientConnectionManager
import org.scalatest.{ BeforeAndAfterAll, FlatSpec, ShouldMatchers }

import scala.util.Try

class LivyServerSpec extends FlatSpec with ShouldMatchers with BeforeAndAfterAll {

  private val server = new LivyServer

  override def beforeAll(): Unit = {
    server.start()
//    server.join()
  }

  override def afterAll(): Unit = {
    server.stop()
    clientBuilder.build().close()
  }

  private val requestConfig = new RequestConfig() {
    override def getConnectTimeout = 5000
    override def isAuthenticationEnabled = true
    override def isContentCompressionEnabled = false
  }

  private val emptyCredentials = new Credentials() {
    def getUserPrincipal = new BasicUserPrincipal("")
    def getPassword = ""
  }

  private def createCredentials(user: String, password: String) = (user, password) match {
    case ("", "") => emptyCredentials
    case _        => new UsernamePasswordCredentials(user, password)
  }

  private def credentialsProvider(user: String = "", password: String = "") = {
    val provider = new BasicCredentialsProvider
    provider.setCredentials(AuthScope.ANY, createCredentials(user, password))
    provider
  }

  private lazy val clientBuilder = HttpClientBuilder.create
    .disableAutomaticRetries
    .evictExpiredConnections
    .evictIdleConnections(5l, TimeUnit.SECONDS)
    .setConnectionManager(new BasicHttpClientConnectionManager)
    .setConnectionReuseStrategy(NoConnectionReuseStrategy.INSTANCE)
    .setDefaultRequestConfig(requestConfig)
    .setMaxConnTotal(1)
    .setUserAgent("livy-client-http")

  private def send[U](request: HttpUriRequest, user: String = "", password: String = "")(f: HttpResponse => U) = {
    val responseAttempt = Try {
      clientBuilder
      .setDefaultCredentialsProvider { credentialsProvider(user, password) }
      .build()
      .execute(request)
    }

    val result = responseAttempt.map { f }

    responseAttempt.foreach { _.close() }
    result.get
  }

  private val sessionRequest = new HttpGet("http://localhost:8998/sessions")

  "LivyServer basic auth" should "disallow connections without Authentication headers" in send(sessionRequest) { response =>
    response.getStatusLine.getStatusCode should be { 401 }
    response.getFirstHeader("WWW-Authenticate") should not be { null }
    response.getFirstHeader("WWW-Authenticate").getValue should startWith { "Basic" }
  }

  "LivyServer basic auth" should "allow connections with Authentication headers" in send(sessionRequest, "user", "user") { response =>
    response.getStatusLine.getStatusCode should be { 200 }
  }

}
