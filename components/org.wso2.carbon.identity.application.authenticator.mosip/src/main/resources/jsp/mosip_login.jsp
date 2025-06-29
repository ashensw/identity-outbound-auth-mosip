<%--
  ~ Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
  ~
  ~ WSO2 LLC. licenses this file to you under the Apache License,
  ~ Version 2.0 (the "License"); you may not use this file except
  ~ in compliance with the License.
  ~ You may obtain a copy of the License at
  ~
  ~    http://www.apache.org/licenses/LICENSE-2.0
  ~
  ~ Unless required by applicable law or agreed to in writing,
  ~ software distributed under the License is distributed on an
  ~ "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  ~ KIND, either express or implied.  See the License for the
  ~ specific language governing permissions and limitations
  ~ under the License.
--%>

<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ page import="java.util.ArrayList" %>
<%@ page import="java.util.Arrays" %>
<%@ page import="java.util.List" %>
<%@ page import="java.util.Map" %>
<%@ page import="org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils" %>
<%@ page import="org.wso2.carbon.identity.application.authentication.endpoint.util.AuthenticationEndpointUtil" %>
<%@ page import="org.wso2.carbon.identity.application.authentication.endpoint.util.EndpointConfigManager" %>
<%@ page import="java.io.File" %>
<%@ page import="org.owasp.encoder.Encode" %>
<%@ page import="java.nio.charset.Charset" %>
<%@ page import="org.apache.commons.codec.binary.Base64" %>

<%@ taglib prefix="layout" uri="org.wso2.identity.apps.taglibs.layout.controller" %>

<%@ include file="includes/localize.jsp" %>
<%@ include file="includes/init-url.jsp" %>

<%-- Branding Preferences --%>
<jsp:directive.include file="includes/branding-preferences.jsp"/>

<%
    request.getSession().invalidate();
    String queryString = request.getQueryString();
    Map<String, String> idpAuthenticatorMapping = null;
    if (request.getAttribute("idpAuthenticatorMap") != null) {
        idpAuthenticatorMapping = (Map<String, String>) request.getAttribute("idpAuthenticatorMap");
    }

    String mosipAuthType = "otp";
    String uin = request.getParameter("uin");
    String idType = request.getParameter("idType");

    // Set label and description based on ID type
    String idTypeLabel = (idType != null && !idType.isEmpty()) ? idType : "UIN";
    String authTypeDesc = "Enter your MOSIP " + idTypeLabel + " to receive an OTP";

    String sessionDataKey = request.getParameter("sessionDataKey");
    String errorMessage = request.getParameter("errorMessage");
    if (errorMessage == null) {
        errorMessage = (String) request.getAttribute("errorMessage");
    }

    // Status and message from the authenticator
    String status = request.getParameter("status");
    String statusMsg = request.getParameter("message");
%>

<%!
        private boolean isMultiAuthAvailable(String multiOptionURI) {
            boolean isMultiAuthAvailable = true;
            if (multiOptionURI == null || multiOptionURI.equals("null")) {
                isMultiAuthAvailable = false;
            } else {
                int authenticatorIndex = multiOptionURI.indexOf("authenticators=");
                if (authenticatorIndex == -1) {
                    isMultiAuthAvailable = false;
                } else {
                    String authenticators = multiOptionURI.substring(authenticatorIndex + 15);
                    int authLastIndex = authenticators.indexOf("&") != -1 ? authenticators.indexOf("&") : authenticators.length();
                    authenticators = authenticators.substring(0, authLastIndex);
                    List<String> authList = Arrays.asList(authenticators.split("%3B"));
                    if (authList.size() < 2) {
                        isMultiAuthAvailable = false;
                    }
                    else if (authList.size() == 2 && authList.contains("backup-code-authenticator%3ALOCAL")) {
                        isMultiAuthAvailable = false;
                    }
                }
            }
            return isMultiAuthAvailable;
        }
%>

<!doctype html>
<html>
<head>
    <script language="JavaScript" type="text/javascript" src="libs/jquery_3.6.0/jquery-3.6.0.min.js"></script>
    <%-- header --%>
    <%
        File headerFile = new File(getServletContext().getRealPath("extensions/header.jsp"));
        if (headerFile.exists()) {
    %>
        <jsp:include page="extensions/header.jsp"/>
    <% } else { %>
        <jsp:include page="includes/header.jsp"/>
    <% } %>
    
    <style>
        .mosip-container {
            margin-top: 20px;
        }
        .countdown {
            margin-top: 10px;
            font-size: 14px;
            color: #dc3545;
        }
    </style>
</head>

<body class="login-portal layout authentication-portal-layout">
    <layout:main layoutName="<%= layout %>" layoutFileRelativePath="<%= layoutFileRelativePath %>" data="<%= layoutData %>" >
        <layout:component componentName="ProductHeader">
            <%-- product-title --%>
            <%
                File productTitleFile = new File(getServletContext().getRealPath("extensions/product-title.jsp"));
                if (productTitleFile.exists()) {
            %>
                <jsp:include page="extensions/product-title.jsp"/>
            <% } else { %>
                <jsp:include page="includes/product-title.jsp"/>
            <% } %>
        </layout:component>
        <layout:component componentName="MainSection">
            <div class="ui segment segment-layout">
                <%-- page content --%>
                <h3 class="ui header">
                    <%=AuthenticationEndpointUtil.i18n(resourceBundle, "login.heading")%>
                </h3>
                <div class="ui divider hidden"></div>
                <div class="ui visible negative message" style="display: none;" id="error-msg"></div>

                <div class="segment-form">
                    <% if (status != null && "PENDING".equalsIgnoreCase(status)) { %>
                        <!-- Authentication on progress -->
                        <div class="align-center" id="inProgressDisplay">
                            <h5 id="authenticationStatusMessage">
                                <%=AuthenticationEndpointUtil.i18n(resourceBundle, "otp.sent")%>
                            </h5>
                        </div>
                    <% } %>

                    <% if (errorMessage != null && !errorMessage.isEmpty()) { %>
                        <div class="ui visible negative message" id="server-error-msg">
                            <%= errorMessage %>
                        </div>
                    <% } %>

                    <form class="ui large form" id="loginForm" action="<%=commonauthURL%>" method="POST">
                        <div class="ui divider hidden"></div>
                        <div class="field">
                            <label><%=AuthenticationEndpointUtil.i18n(resourceBundle, "enter.uin")%></label>
                            <div class="ui fluid left icon input addon-wrapper">
                                <input 
                                    type="text" 
                                    id="uin"  
                                    name="uin" 
                                    tabindex="1" 
                                    placeholder="<%=AuthenticationEndpointUtil.i18n(resourceBundle, "enter.uin")%>" 
                                    aria-required="true">
                                <i aria-hidden="true" class="user icon"></i>
                            </div>
                        </div>

                        <input id="sessionDataKey" type="hidden" name="sessionDataKey"
                            value='<%=Encode.forHtmlAttribute(request.getParameter("sessionDataKey"))%>' />
                        <input type="hidden" name="mosip.auth.type" value="<%= mosipAuthType %>"/>

                        <% if (idType != null && !idType.isEmpty()) { %>
                        <input type="hidden" name="idType" value="<%= idType %>"/>
                        <% } %>
                        
                        <input id="multiOptionURI" type="hidden" name="multiOptionURI"
                            value='<%=Encode.forHtmlAttribute(request.getParameter("multiOptionURI"))%>' />

                        <div class="buttons">
                            <button type="submit" class="ui primary fluid button" tabindex="4" role="button">
                                <%=AuthenticationEndpointUtil.i18n(resourceBundle, "send.otp")%>
                            </button>
                        </div>
                    </form>
                </div>

                <div class="ui divider hidden"></div>
                <%
                    String multiOptionURI = request.getParameter("multiOptionURI");
                    if (multiOptionURI != null && AuthenticationEndpointUtil.isValidMultiOptionURI(multiOptionURI) &&
                        isMultiAuthAvailable(multiOptionURI)) {
                %>
                    <div class="text-center">
                        <a class="ui primary basic button link-button" id="goBackLink"
                        href='<%=Encode.forHtmlAttribute(multiOptionURI)%>'>
                            <%=AuthenticationEndpointUtil.i18n(resourceBundle, "choose.other.option")%>
                        </a>
                    </div>
                <%
                    }
                %>
            </div>
        </layout:component>
        <layout:component componentName="ProductFooter">
            <%-- product-footer --%>
            <%
                File productFooterFile = new File(getServletContext().getRealPath("extensions/product-footer.jsp"));
                if (productFooterFile.exists()) {
            %>
                <jsp:include page="extensions/product-footer.jsp"/>
            <% } else { %>
                <jsp:include page="includes/product-footer.jsp"/>
            <% } %>
        </layout:component>
        <layout:dynamicComponent filePathStoringVariableName="pathOfDynamicComponent">
            <jsp:include page="${pathOfDynamicComponent}" />
        </layout:dynamicComponent>
    </layout:main>

    <%-- footer --%>
    <%
        File footerFile = new File(getServletContext().getRealPath("extensions/footer.jsp"));
        if (footerFile.exists()) {
    %>
        <jsp:include page="extensions/footer.jsp"/>
    <% } else { %>
        <jsp:include page="includes/footer.jsp"/>
    <% } %>
    
    <%
        String toEncode = EndpointConfigManager.getAppName() + ":" + String.valueOf(EndpointConfigManager.getAppPassword());
        byte[] encoding = Base64.encodeBase64(toEncode.getBytes());
        String authHeader = new String(encoding, Charset.defaultCharset());
        String header = "Client " + authHeader;
    %>

    <script type="text/javascript">
        $(document).ready(function() {
            var error_msg = document.getElementById("error-msg");

            if ("<%= status %>" === "PENDING") {
                document.getElementById("loginForm").style.display = 'block';
                document.getElementById("inProgressDisplay").style.display = 'block';
            }
        });

        function handleError(msg) {
            var error_message = document.getElementById("error-msg");
            error_message.innerHTML = msg;
            error_message.style.display = "block";
        }

        function loginFormOnSubmit() {
            var uin = document.getElementById("uin").value;

            if (uin === '') {
                handleError('<%=AuthenticationEndpointUtil.i18n(resourceBundle, "please.enter.uin")%>');
                return false;
            }

            document.getElementById("error-msg").style.display = 'none';
            return true;
        }

        // Override the form submission to validate first
        $("#loginForm").submit(function(event) {
            if (!loginFormOnSubmit()) {
                event.preventDefault();
            }
        });
    </script>
    <% if (status != null && ("CANCELED".equals(status) || "FAILED".equals(status) || "INVALID_REQUEST".equals(status))) { %>
    <script type="text/javascript">
        document.addEventListener("DOMContentLoaded", function() {
            var error_msg = document.getElementById("error-msg");
            error_msg.innerHTML = "<%= Encode.forJavaScript(statusMsg) %>";
            error_msg.style.display = "block";
        });
    </script>
    <% } %>
</body>
</html>
