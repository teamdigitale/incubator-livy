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

package org.apache.livy.server.batch

import javax.servlet.http.HttpServletRequest

import org.apache.livy.LivyConf
import org.apache.livy.LivyConf.AUTH_TYPE
import org.apache.livy.server.recovery.SessionStore
import org.apache.livy.server.{AccessManager, SessionServlet}
import org.apache.livy.sessions.BatchSessionManager
import org.apache.livy.utils.AppInfo

case class BatchSessionView(
                             id: Long,
                             state: String,
                             appId: Option[String],
                             appInfo: AppInfo,
                             log: Seq[String])

class BatchSessionServlet(
                           sessionManager: BatchSessionManager,
                           sessionStore: SessionStore,
                           livyConf: LivyConf,
                           accessManager: AccessManager)
  extends SessionServlet(sessionManager, livyConf, accessManager) {

  override protected def createSession(req: HttpServletRequest): BatchSession = {
    val createRequest = bodyAs[CreateBatchRequest](req)
    val proxyUser = if (livyConf.get(AUTH_TYPE) == "basic") {
      import org.pac4j.core.context.J2EContext
      import org.pac4j.core.profile.{CommonProfile, ProfileManager}
      val context = new J2EContext(request, response)
      val manager = new ProfileManager[CommonProfile](context)
      val profile = manager.get(false)
      if (profile.isPresent)
        Some(profile.get().getUsername)
      else
        None
    } else
      checkImpersonation(createRequest.proxyUser, req)
    BatchSession.create(
      sessionManager.nextId(), createRequest, livyConf, remoteUser(req), proxyUser, sessionStore)
  }

  override protected[batch] def clientSessionView(
                                                   session: BatchSession,
                                                   req: HttpServletRequest): Any = {
    val logs =
      if (hasViewAccess(session.owner, req)) {
        val lines = session.logLines()

        val size = 10
        val from = math.max(0, lines.length - size)
        val until = from + size

        lines.view(from, until).toSeq
      } else {
        Nil
      }
    BatchSessionView(session.id, session.state.toString, session.appId, session.appInfo, logs)
  }

}
