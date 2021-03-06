/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.livy.server

import java.security.InvalidParameterException
import java.time.Duration

import org.ldaptive.{ BindConnectionInitializer, ConnectionConfig, Credential, DefaultConnectionFactory }
import org.ldaptive.auth.{ Authenticator, FormatDnResolver, PooledBindAuthenticationHandler }
import org.ldaptive.pool._
import org.ldaptive.ssl.SslConfig
import org.pac4j.core.client.Clients
import org.pac4j.core.config.Config
import org.pac4j.http.client.direct.{ DirectBasicAuthClient, HeaderClient }
import org.pac4j.http.credentials.authenticator.test.SimpleTestUsernamePasswordAuthenticator
import org.pac4j.jwt.config.signature.SecretSignatureConfiguration
import org.pac4j.jwt.credentials.authenticator.JwtAuthenticator
import org.pac4j.ldap.profile.service.LdapProfileService
import org.apache.livy.LivyConf
import org.pac4j.http.client.indirect.IndirectBasicAuthClient

object InitPac4jSecurity {

  implicit final class RichLivyConf(livyConf: LivyConf) extends AnyRef {
    def optionalGet(key: String): Option[String] = Option(livyConf.get(key))
  }

  var livyConf: Option[LivyConf] = None
  var config: Option[Config] = None

  private def getLdapAuthenticator = {
    val dnResolver = new FormatDnResolver
    livyConf.foreach(livyConf => dnResolver.
      setFormat(livyConf.
        optionalGet("livy.server.pac4j.ldap.user_dn_pattern").
        getOrElse(
          throw new InvalidParameterException(
            s"Missing mandatory parameter livy.server.pac4j.ldap.user_dn_pattern")
        )
      ))
    val connectionConfig = new ConnectionConfig
    livyConf.foreach(livyConf => connectionConfig.setConnectTimeout(
      Duration.ofMillis(livyConf.
        optionalGet("livy.server.pac4j.connect_timeout").
        getOrElse("500").toLong)
    ))
    livyConf.foreach(livyConf => connectionConfig.setResponseTimeout(
      Duration.ofMillis(livyConf.
        optionalGet("livy.server.pac4j.response_timeout").
        getOrElse("1000").toLong)
    ))
    livyConf.foreach(livyConf =>
      connectionConfig.setLdapUrl(livyConf.get("livy.server.pac4j.ldap.url")))
    livyConf.foreach(livyConf =>
      connectionConfig.setConnectionInitializer(
        new BindConnectionInitializer(livyConf.optionalGet("livy.server.pac4j.ldap.bind_dn").
          getOrElse(
            throw new InvalidParameterException(
              s"Missing mandatory parameter livy.server.pac4j.ldap.bind_dn"
            )
          ),
          new Credential(livyConf.get("livy.server.pac4j.ldap.bind_pwd")))))
    // TODO Shall we keep SSL mandatory
    connectionConfig.setUseSSL(true)
    val sslConfig = new SslConfig()
    // TODO no more certificate validation, shall we keep it in this way?
    sslConfig.setTrustManagers()
    connectionConfig.setSslConfig(sslConfig)
    val connectionFactory = new DefaultConnectionFactory
    connectionFactory.setConnectionConfig(connectionConfig)
    val poolConfig = new PoolConfig
    poolConfig.setMinPoolSize(1) // TODO magicnumber
    poolConfig.setMaxPoolSize(2) // TODO magicnumber
    poolConfig.setValidateOnCheckOut(true)
    poolConfig.setValidateOnCheckIn(true)
    poolConfig.setValidatePeriodically(false)
    val searchValidator = new SearchValidator
    val pruneStrategy = new IdlePruneStrategy
    val connectionPool = new BlockingConnectionPool
    connectionPool.setPoolConfig(poolConfig)
    connectionPool.setBlockWaitTime(Duration.ofMillis(1000)) // TODO magicnumber
    connectionPool.setValidator(searchValidator)
    connectionPool.setPruneStrategy(pruneStrategy)
    connectionPool.setConnectionFactory(connectionFactory)
    connectionPool.initialize()
    val pooledConnectionFactory = new PooledConnectionFactory
    pooledConnectionFactory.setConnectionPool(connectionPool)
    val handler = new PooledBindAuthenticationHandler
    handler.setConnectionFactory(pooledConnectionFactory)
    val ldaptiveAuthenticator = new Authenticator
    ldaptiveAuthenticator.setDnResolver(dnResolver)
    ldaptiveAuthenticator.setAuthenticationHandler(handler)
    // pac4j:
    val authenticator = new LdapProfileService(connectionFactory, ldaptiveAuthenticator, "dummy")
    authenticator.setAttributes("")
    livyConf.foreach(livyConf => authenticator.
      setUsernameAttribute(
        livyConf.
          optionalGet("livy.server.pac4j.ldap.username_attribute").
          getOrElse("uid")
      ))
    authenticator
  }

  def apply(conf: LivyConf): Unit = {
    livyConf = Some(conf)
    val authenticatorConf = livyConf.map(_.get("livy.server.pac4j.authenticator"))
    val authenticator = authenticatorConf match {
      case Some("ldap") => getLdapAuthenticator
      case Some("test") => new SimpleTestUsernamePasswordAuthenticator
      case _ => getLdapAuthenticator
    }
    val directBasicAuthClient = new DirectBasicAuthClient(authenticator)
    val secret = livyConf.flatMap { conf => Option(conf.get("livy.server.pac4j.jwt_secret")) }
    val jwtAuthenticator = new JwtAuthenticator()
    secret.foreach { secret =>
      jwtAuthenticator.addSignatureConfiguration { new SecretSignatureConfiguration(secret) }
    }
    val parameterClient = new HeaderClient("Authorization", "Bearer ", jwtAuthenticator)
    config = Some(new Config(new Clients(directBasicAuthClient, parameterClient)))
  }
}
