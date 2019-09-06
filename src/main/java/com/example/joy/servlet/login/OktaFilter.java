/*
 * Copyright 2019-Present Okta, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.example.joy.servlet.login;

import com.okta.authn.sdk.resource.User;
import com.okta.commons.lang.Strings;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * A primitive authentication Servlet Filter. This is <strong>NOT</strong> a production ready application. It's goal is to demonstrate how to integrate Okta's Authentication SDK into an existing Servlet based framework. If you are starting from scratch we strongly recommend using OIDC/OAuth 2.0 via our Spring Boot integration or other OAuth 2.0 library.
 *
 * @see <a href="https://github.com/okta/samples-java-spring">Okta Spring Samples</a>
 * @see <a href="https://www.owasp.org/index.php/OWASP_Top_Ten_Cheat_Sheet">OWASP Top Ten Cheat Sheet</a>
 */
public class OktaFilter implements Filter {

    static final String USER_SESSION_KEY = User.class.getName();

    private AuthenticationActions actions;

    public OktaFilter(AuthenticationActions actions) {
        this.actions = actions;
    }

    @Override
    public void init(FilterConfig filterConfig) {}

    @Override
    public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain) throws IOException, ServletException {

        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) resp;
        String path = request.getServletPath();

        // allow anonymous access to static resources and anything under /authn/ and the root index.jsp
        if (isStaticAsset(request) || path.startsWith("/authn/") ) {
            chain.doFilter(request, response);
            return;
        }

        // check if we have a current user in the session
        if (isAuthenticated(request)) {
            chain.doFilter(request, response);
            return;
        }

        // no authenticated user found in session
        // redirect to /authn/login
        //response.sendRedirect("/authn/login");

        response.sendRedirect("https://dev-314363.okta.com/oauth2/default/v1/authorize?client_id=0oa1a9wr5eDsss0EJ357&response_type=token&scope=openid&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fauthn%2Flogin&state=state-296bc9a0-a2a2-4a57-be1a-d0e2fd9bb601&nonce=foo");
    }

    @Override
    public void destroy() {}

    private boolean isAuthenticated(HttpServletRequest request) {

        String token = request.getParameter("hashToken");
        if(!Strings.isEmpty(token) && actions.isValidToken(token)) {
            return true;
        }

        return false;

        //return request.getSession(false) != null && request.getSession().getAttribute(USER_SESSION_KEY) != null;
    }

    private boolean isStaticAsset(HttpServletRequest request) {
        String path = request.getServletPath();
        return path.startsWith("/static/") || path.equals("/favicon.ico");
    }
}